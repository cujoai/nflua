/*
 * This file is Confidential Information of Cujo LLC.
 * Copyright (c) 2017 CUJO LLC. All rights reserved.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/version.h>

#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/netlink.h>
#include <net/ip.h>
#include <net/sock.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/kfifo.h>
#include <linux/jiffies.h>
#include <linux/timer.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <luadata.h>

#include "xt_lua.h"
#include "nf_util.h"
#include "luautil.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pedro Caldas Tammela <pctammela@getcujo.com>");
MODULE_AUTHOR("Lourival Vieira Neto <lourival.neto@getcujo.com>");
MODULE_AUTHOR("Iruatã Souza <iru@getcujo.com>");

MODULE_DESCRIPTION("Netfilter Lua module");

extern int luaopen_json(lua_State* L);

extern int luaopen_base64(lua_State* L);

static struct sock *sock;

static lua_State *L = NULL;

static DEFINE_SPINLOCK(lock);

struct nflua_ctx {
	struct sk_buff *skb;
	struct xt_action_param *par;
};

struct nftimer_ctx {
       struct timer_list timer;
       lua_State *L;
};

static void nflua_destroy(const struct xt_mtdtor_param *par)
{
}

static int nflua_checkentry(const struct xt_mtchk_param *par)
{
	return 0;
}

int nflua_msghandler(lua_State *L)
{
	const char *msg = lua_tostring(L, 1);
	if (msg == NULL) {
		if (luaL_callmeta(L, 1, "__tostring") &&
		    lua_type(L, -1) == LUA_TSTRING)
			return 1;
		else
			msg = lua_pushfstring(L, "(error object is a %s value)",
				luaL_typename(L, 1));
	}
	luaL_traceback(L, L, msg, 1);
	return 1;
}

static int nflua_pcall(lua_State *L, int nargs, int nresults)
{
	int status;
	int base = lua_gettop(L) - nargs;
	lua_pushcfunction(L, nflua_msghandler);
	lua_insert(L, base);
	status = lua_pcall(L, nargs, nresults, base);
	lua_remove(L, base);
	return status;
}

static bool nflua_match(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_lua_mtinfo *info = par->matchinfo;
	struct nflua_ctx ctx = {.skb = (struct sk_buff *) skb, .par = par};
	bool match = false;
	int error  = 0;
	int frame = LUA_NOREF;
	int packet = LUA_NOREF;

	spin_lock(&lock);
	luaU_setenv(L, &ctx, struct nflua_ctx);

	if (lua_getglobal(L, info->func) != LUA_TFUNCTION) {
		pr_err("%s: %s\n", "couldn't find match function", info->func);
		goto out;
	}

	frame = ldata_newref(L, skb_mac_header(skb), skb_mac_header_len(skb));
	packet = ldata_newref(L, skb->data, skb->len);

	error = nflua_pcall(L, 2, 1);

	ldata_unref(L, frame);
	ldata_unref(L, packet);

	if (error) {
		pr_err("%s\n", lua_tostring(L, -1));
		goto out;
	}

	par->hotdrop = (bool) lua_isnil(L, -1); /* cache miss? */
	match = par->hotdrop ? false : (bool) lua_toboolean(L, -1);
out:
	lua_pop(L, 1); /* result, info->func or error */
	spin_unlock(&lock);
	return match;
}

static int nflua_reply(lua_State *L)
{
	size_t len;
	unsigned char *type;
	unsigned char *msg;
	struct nflua_ctx *ctx = luaU_getenv(L, struct nflua_ctx);

	if (ctx == NULL)
		goto error;

	type = (unsigned char *)luaL_checkstring(L, 1);
	msg = (unsigned char *)luaL_checklstring(L, 2, &len);

	switch(type[0]) {
	case 't':
		if (tcp_reply(ctx->skb, ctx->par, msg, len) != 0)
			goto error;
		break;
	default:
		goto error;
	}

	return 0;
error:
	return luaL_error(L, "couldn't reply a packet");
}

#define nlmsg_send(sock, skb, pid, group) \
	((group == 0) ? nlmsg_unicast(sock, skb, pid) : \
		nlmsg_multicast(sock, skb, pid, group, 0))

static int nflua_netlink(lua_State *L)
{
	size_t size;
	const char *payload = luaL_checklstring(L, 1, &size);
	int pid = luaL_checkinteger(L, 2);
	int group = luaL_optinteger(L, 3, 0);
	int flags = luaL_optinteger(L, 4, 0);
	struct sk_buff *skb = nlmsg_new(size, GFP_KERNEL);
	struct nlmsghdr *nlh;

	if (skb == NULL)
		return luaL_error(L, "insufficient memory");

	if ((nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, size, flags)) == NULL) {
		kfree_skb(skb);
		return luaL_error(L, "message too long");
	}

	memcpy(nlmsg_data(nlh), payload, size);

	if (nlmsg_send(sock, skb, pid, group) < 0)
		return luaL_error(L, "failed to send message");

	lua_pushinteger(L, (lua_Integer) size);
	return 1;
}

#define NFLUA_SKBUFF  "lskb"
#define tolskbuff(L) ((struct sk_buff **) luaL_checkudata(L, 1, NFLUA_SKBUFF))
#define lnewskbuff(L) \
	((struct sk_buff **) lua_newuserdata(L, sizeof(struct sk_buff *)))

static int nflua_skb_send(lua_State *L)
{
	struct sk_buff *nskb, **lskb = tolskbuff(L);
	size_t len;
	unsigned char *payload;

	if (*lskb == NULL)
		return luaL_error(L, "closed packet");

	payload = (unsigned char *)lua_tolstring(L, 2, &len);
	if (payload != NULL) {
		nskb = tcp_payload(*lskb, payload, len);
		if (nskb == NULL)
			return luaL_error(L, "unable to set tcp payload");

		/* Original packet is not needed anymore */
		kfree_skb(*lskb);
		*lskb = NULL;
	} else {
		if (unlikely(skb_shared(*lskb)))
			return luaL_error(L, "cannot send a shared skb");
		nskb = *lskb;
	}

	if (route_me_harder(nskb)) {
		pr_err("unable to route packet");
		goto error;
	}

	if (tcp_send(nskb) != 0) {
		pr_err("unable to send packet");
		goto error;
	}

	*lskb = NULL;
	return 0;
error:
	if (*lskb == NULL && nskb != NULL)
		kfree_skb(nskb);
	return luaL_error(L, "send packet error");
}

static int nflua_getpacket(lua_State *L)
{
	struct sk_buff **lskb;
	struct nflua_ctx *ctx = luaU_getenv(L, struct nflua_ctx);

	if (ctx == NULL)
		return luaL_error(L, "couldn't get packet");

	lskb = lnewskbuff(L);
	*lskb = skb_get(ctx->skb);
	luaL_setmetatable(L, NFLUA_SKBUFF);

	return 1;
}

static int nflua_skb_free(lua_State *L)
{
	struct sk_buff **lskb = tolskbuff(L);

	if (*lskb != NULL) {
		kfree_skb(*lskb);
		*lskb = NULL;
	}

	return 0;
}

static int nflua_skb_tostring(lua_State *L)
{
	struct sk_buff *skb = *tolskbuff(L);

	if (skb == NULL) {
		lua_pushliteral(L, "packet closed");
	} else {
		lua_pushfstring(L,
			"packet: { len:%d data_len:%d users:%d "
			"cloned:%d dataref:%d frags:%d }",
			skb->len,
			skb->data_len,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
			refcount_read(&skb->users),
#else
			atomic_read(&skb->users),
#endif
			skb->cloned,
			atomic_read(&skb_shinfo(skb)->dataref),
			skb_shinfo(skb)->nr_frags);
	}

	return 1;
}

static int nflua_time(lua_State *L)
{
	struct timespec ts;

	getnstimeofday(&ts);
	lua_pushinteger(L, (lua_Integer)ts.tv_sec);
	lua_pushinteger(L, (lua_Integer)(ts.tv_nsec / NSEC_PER_MSEC));

	return 2;
}

static void timeout_cb(unsigned long data)
{
       struct nftimer_ctx *ctx = (struct nftimer_ctx *)data;
       lua_State *L = ctx->L;
       int base;

       spin_lock(&lock);
       base = lua_gettop(L);

       /*
        * if we have already called ltimer_destroy for this timer,
        * the lua callback is going to be nil, so we just bail out.
        */
       if (!luaU_getuvalue(L, ctx, LUA_TFUNCTION))
               goto out;

       if (lua_pcall(L, 0, 0, 0) != 0) {
               pr_warn("%s", lua_tostring(L, -1));
               goto out;
       }

out:
       luaU_unregisterudata(L, ctx);
       lua_settop(L, base);
       spin_unlock(&lock);
}

static int ltimer_create(lua_State *L)
{
       struct nftimer_ctx *ctx = lua_newuserdata(L, sizeof(struct nftimer_ctx));
       unsigned long msecs = luaL_checkinteger(L, 1);

       luaL_checktype(L, 2, LUA_TFUNCTION);

       ctx->L = L;

       setup_timer(&ctx->timer, timeout_cb, (unsigned long)ctx);
       if (mod_timer(&ctx->timer, jiffies + msecs_to_jiffies(msecs)))
               return luaL_error(L, "error setting timer");

       luaU_registerudata(L, -1, ctx); /* shouldn't gc context */
       luaU_setuvalue(L, -1, 2); /* store callback */

       return 1;
}

static int ltimer_destroy(lua_State *L)
{
       struct nftimer_ctx *ctx = lua_touserdata(L, 1);
       int base = lua_gettop(L);

       /* the timer callback has already cleaned the context up */
       if (ctx == NULL)
               return 0;

       del_timer(&ctx->timer);

       luaU_unregisterudata(L, ctx);
       lua_settop(L, base);
       return 0;
}

static const luaL_Reg timerlib[] = {
       {"create", ltimer_create},
       {"destroy", ltimer_destroy},
       {NULL, NULL}
};

int luaopen_timer(lua_State *L)
{
       luaL_newlib(L, timerlib);
       return 1;
}

static const luaL_Reg nflua_lib[] = {
	{"reply", nflua_reply},
	{"netlink", nflua_netlink},
	{"time", nflua_time},
	{"getpacket", nflua_getpacket},
	{NULL, NULL}
};

static const luaL_Reg nflua_skb_ops[] = {
	{"send", nflua_skb_send},
	{"close", nflua_skb_free},
	{"__gc", nflua_skb_free},
	{"__tostring", nflua_skb_tostring},
	{NULL, NULL}
};

int luaopen_nf(lua_State *L)
{
	luaL_newmetatable(L, NFLUA_SKBUFF);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, nflua_skb_ops, 0);
	lua_pop(L, 1);

	luaL_newlib(L, nflua_lib);
	return 1;
}
EXPORT_SYMBOL(luaopen_nf);

static struct xt_match nflua_mt_reg __read_mostly = {
	.name       = "lua",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = nflua_match,
	.checkentry = nflua_checkentry,
	.destroy    = nflua_destroy,
	.matchsize  = sizeof(struct xt_lua_mtinfo),
	.me         = THIS_MODULE
};

#define nflua_dostring(L, b, s, n)	\
	(luaL_loadbufferx(L, b, s, n, "t") ||	\
	 nflua_pcall(L, 0, 0))


static void nflua_input(struct sk_buff *skb)
{
	struct net *net = sock_net(skb->sk);
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	const char *script = (const char *) nlmsg_data(nlh);
	const char *name = script;
	int len = nlmsg_len(nlh);
	int namelen = strnlen(name, len);

	if (!ns_capable(net->user_ns, CAP_NET_ADMIN)) {
		pr_err("operation not permitted");
		return;
	}

	if (namelen != len) {
		script += namelen + 1;
		len -= namelen + 1;
	}

	spin_lock_bh(&lock);
	luaU_setenv(L, NULL, struct nflua_ctx);

	if (nflua_dostring(L, script, len, name) != 0) {
		pr_err("%s\n", lua_tostring(L, -1));
		lua_pop(L, 1); /* error */
	}
	spin_unlock_bh(&lock);
}

static int __init xt_lua_init(void)
{

	struct netlink_kernel_cfg cfg = {
		.groups = 0,
		.input = nflua_input,
	};

	if (nf_util_init() == NULL)
		return -EFAULT;

	spin_lock(&lock);
	L = luaL_newstate();

	if (L == NULL) {
		spin_unlock(&lock);
		return -ENOMEM;
	}

	luaL_openlibs(L);

	luaL_requiref(L, "nf", luaopen_nf, 1);
	luaL_requiref(L, "data", luaopen_data, 1);
	luaL_requiref(L, "json", luaopen_json, 1);
	luaL_requiref(L, "base64", luaopen_base64, 1);
	luaL_requiref(L, "timer", luaopen_timer, 1);
	lua_pop(L, 5); /* nf, data, json, base64, timer */
	spin_unlock(&lock);

	sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
	if (sock == NULL)
		return -ENOMEM;

	return xt_register_match(&nflua_mt_reg);
}

static void __exit xt_lua_exit(void)
{
	spin_lock(&lock);
	if (L != NULL)
		lua_close(L);

	L = NULL;
	spin_unlock(&lock);

	netlink_kernel_release(sock);

	return xt_unregister_match(&nflua_mt_reg);
}

module_init(xt_lua_init);
module_exit(xt_lua_exit);
