/*
 * Copyright (C) 2017-2019 CUJO LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
#include <net/netns/generic.h>
#include <net/netfilter/nf_conntrack.h>

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
static inline u32 skb_mac_header_len(const struct sk_buff *skb)
{
	return skb->network_header - skb->mac_header;
}
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pedro Caldas Tammela <pctammela@getcujo.com>");
MODULE_AUTHOR("Lourival Vieira Neto <lourival.neto@getcujo.com>");
MODULE_AUTHOR("Iruatã Souza <iru@getcujo.com>");

MODULE_DESCRIPTION("Netfilter Lua module");

#define NFLUA_SOCK "nflua_sock"

static int xt_lua_net_id __read_mostly;
struct xt_lua_net {
	lua_State *L;
	spinlock_t lock;
};

static inline struct xt_lua_net *xt_lua_pernet(struct net *net)
{
	return net_generic(net, xt_lua_net_id);
}

#define NFLUA_SKBCLONE "nflua_skbclone"
#define NFLUA_CTXENTRY "nflua_ctx"
struct nflua_ctx {
	struct sk_buff *skb;
	struct xt_action_param *par;
	int frame;
	int packet;
};

struct nftimer_ctx {
       struct timer_list timer;
       struct xt_lua_net *xt_lua;
};

static void nflua_destroy(const struct xt_mtdtor_param *par)
{
}

static int nflua_checkentry(const struct xt_mtchk_param *par)
{
	return 0;
}

static int nflua_msghandler(lua_State *L)
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

static int nflua_domatch(lua_State *L)
{
	struct nflua_ctx *ctx = lua_touserdata(L, 1);
	struct sk_buff *skb = ctx->skb;
	const struct xt_lua_mtinfo *info = ctx->par->matchinfo;

	luaU_setregval(L, NFLUA_CTXENTRY, ctx);
	luaU_setregval(L, NFLUA_SKBCLONE, NULL);

	if (lua_getglobal(L, info->func) != LUA_TFUNCTION)
		return luaL_error(L, "couldn't find match function: %s\n", info->func);

	if (skb_linearize(skb) != 0)
		return luaL_error(L, "skb linearization failed.\n");

	ctx->frame = ldata_newref(L, skb_mac_header(skb), skb_mac_header_len(skb));
	ctx->packet = ldata_newref(L, skb->data, skb->len);

	lua_call(L, 2, 1);

	return 1;
}

static bool nflua_match(const struct sk_buff *skb, struct xt_action_param *par)
{
	struct nflua_ctx ctx = {.skb = (struct sk_buff *) skb, .par = par,
		.frame = LUA_NOREF, .packet = LUA_NOREF};
	struct xt_lua_net *xt_lua = xt_lua_pernet(xt_net(par));
	const struct xt_lua_mtinfo *info = par->matchinfo;
	lua_State *L;
	bool match = false;
	int base;

	if ((info->flags & XT_NFLUA_TCP_PAYLOAD) && tcp_payload_length(skb) <= 0)
		return match;

	spin_lock(&xt_lua->lock);
	if (xt_lua->L == NULL) {
		pr_err("invalid lua state");
		goto unlock;
	}
	L = xt_lua->L;

	base = lua_gettop(L);
	lua_pushcfunction(L, nflua_domatch);
	lua_pushlightuserdata(L, (void *) &ctx);

	if (nflua_pcall(L, 1, 1)) {
		pr_err("%s\n", lua_tostring(L, -1));
		goto cleanup;
	}

	match = (bool) lua_toboolean(L, -1);

cleanup:
	ldata_unref(L, ctx.frame);
	ldata_unref(L, ctx.packet);
	lua_settop(L, base);
unlock:
	spin_unlock(&xt_lua->lock);
	return match;
}

static int nflua_reply(lua_State *L)
{
	size_t len;
	unsigned char *type;
	unsigned char *msg;
	struct nflua_ctx *ctx;

	luaU_getregval(L, NFLUA_CTXENTRY, &ctx);
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
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct sock *sock;

	luaU_getregval(L, NFLUA_SOCK, &sock);
	if (sock == NULL)
		return luaL_error(L, "invalid netlink socket");

	skb = nlmsg_new(size, GFP_ATOMIC);
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
	struct nflua_ctx *ctx;

	luaU_getregval(L, NFLUA_CTXENTRY, &ctx);
	if (ctx == NULL)
		return luaL_error(L, "couldn't get packet context");

	lua_getfield(L, LUA_REGISTRYINDEX, NFLUA_SKBCLONE);
	if (!lua_isuserdata(L, -1)) {
		lskb = lnewskbuff(L);
		if ((*lskb = skb_copy(ctx->skb, GFP_ATOMIC)) == NULL)
			return luaL_error(L, "couldn't copy packet");

		luaL_setmetatable(L, NFLUA_SKBUFF);
		lua_pushvalue(L, -1);
		lua_setfield(L, LUA_REGISTRYINDEX, NFLUA_SKBCLONE);
	}

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

#define NFLUA_TIMER "ltimer"

static int nflua_time(lua_State *L)
{
	struct timespec ts;

	getnstimeofday(&ts);
	lua_pushinteger(L, (lua_Integer)ts.tv_sec);
	lua_pushinteger(L, (lua_Integer)(ts.tv_nsec / NSEC_PER_MSEC));

	return 2;
}

static void __timeout_cb(struct nftimer_ctx *ctx)
{
       struct xt_lua_net *xt_lua = ctx->xt_lua;
       int base;

       spin_lock(&xt_lua->lock);
       if (xt_lua->L == NULL) {
               pr_err("invalid lua state");
               goto out2;
       }
       base = lua_gettop(xt_lua->L);

       /*
        * if we have already called ltimer_destroy for this timer,
        * the lua callback is going to be nil, so we just bail out.
        */
       if (!luaU_getuvalue(xt_lua->L, ctx, LUA_TFUNCTION))
               goto out;

       if (lua_pcall(xt_lua->L, 0, 0, 0) != 0) {
               pr_warn("%s", lua_tostring(xt_lua->L, -1));
               goto out;
       }

out:
       luaU_unregisterudata(xt_lua->L, ctx);
       lua_settop(xt_lua->L, base);
out2:
       spin_unlock(&xt_lua->lock);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void timeout_cb(struct timer_list *t)
{
       struct nftimer_ctx *ctx = from_timer(ctx, t, timer);
       __timeout_cb(ctx);
}
#else
static void timeout_cb(unsigned long data)
{
       __timeout_cb((struct nftimer_ctx *)data);
}
#endif

static int ltimer_create(lua_State *L)
{
       struct nftimer_ctx *ctx;
       unsigned long msecs = luaL_checkinteger(L, 1);

       luaL_checktype(L, 2, LUA_TFUNCTION);

       ctx = lua_newuserdata(L, sizeof(struct nftimer_ctx));
       ctx->xt_lua = luaU_getenv(L, struct xt_lua_net);
       luaL_setmetatable(L, NFLUA_TIMER);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
       timer_setup(&ctx->timer, timeout_cb, 0);
#else
       setup_timer(&ctx->timer, timeout_cb, (unsigned long)ctx);
#endif
       if (mod_timer(&ctx->timer, jiffies + msecs_to_jiffies(msecs)))
               return luaL_error(L, "error setting timer");

       luaU_registerudata(L, -1, ctx); /* shouldn't gc context */
       luaU_setuvalue(L, -1, 2); /* store callback */

       return 1;
}

static int ltimer_destroy(lua_State *L)
{
       struct nftimer_ctx *ctx =
               (struct nftimer_ctx *) luaL_checkudata(L, 1, NFLUA_TIMER);
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

static const luaL_Reg ltimer_ops[] = {
	{"__gc", ltimer_destroy},
	{NULL, NULL}
};

int luaopen_timer(lua_State *L)
{
	luaL_newmetatable(L, NFLUA_TIMER);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, ltimer_ops, 0);
	lua_pop(L, 1);

	luaL_newlib(L, timerlib);
	return 1;
}
EXPORT_SYMBOL(luaopen_timer);

int nflua_connid(lua_State *L)
{
	struct nflua_ctx *ctx;
	enum ip_conntrack_info info;
	struct nf_conn *conn;

	luaU_getregval(L, NFLUA_CTXENTRY, &ctx);
	if (ctx == NULL)
		return luaL_error(L, "couldn't get packet context");

	conn = nf_ct_get(ctx->skb, &info);
	lua_pushlightuserdata(L, conn);

	return 1;
}

static const luaL_Reg nflua_lib[] = {
	{"reply", nflua_reply},
	{"netlink", nflua_netlink},
	{"time", nflua_time},
	{"getpacket", nflua_getpacket},
	{"connid", nflua_connid},
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
	struct xt_lua_net *xt_lua = xt_lua_pernet(net);
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	const char *script = (const char *) nlmsg_data(nlh);
	const char *name = script;
	int len = nlmsg_len(nlh);
	int namelen = strnlen(name, len);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
#else
	if (!capable(CAP_NET_ADMIN))
#endif
	{
		pr_err("operation not permitted");
		return;
	}

	if (namelen != len) {
		script += namelen + 1;
		len -= namelen + 1;
	}

	spin_lock_bh(&xt_lua->lock);
	if (xt_lua->L == NULL) {
		pr_err("invalid lua state");
		goto out;
	}
	if (nflua_dostring(xt_lua->L, script, len, name) != 0) {
		pr_err("%s\n", lua_tostring(xt_lua->L, -1));
		lua_pop(xt_lua->L, 1); /* error */
	}
out:
	spin_unlock_bh(&xt_lua->lock);
}

static int __net_init xt_lua_net_init(struct net *net)
{
	struct xt_lua_net *xt_lua = xt_lua_pernet(net);
	struct sock *sock;

	unsigned int groups = 0;
	void (*input)(struct sk_buff *skb) = nflua_input;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	struct netlink_kernel_cfg cfg = {
		.groups = groups,
		.input = input,
	};
#endif

	lua_State *L;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	sock = netlink_kernel_create(net, NETLINK_USERSOCK, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	sock = netlink_kernel_create(net, NETLINK_USERSOCK, THIS_MODULE, &cfg);
#else
	sock = netlink_kernel_create(net, NETLINK_USERSOCK, groups, input,
	                             NULL, THIS_MODULE);
#endif
	if (sock == NULL)
		return -ENOMEM;

	spin_lock_init(&xt_lua->lock);

	spin_lock_bh(&xt_lua->lock);
	xt_lua->L = L = luaL_newstate();
	if (L == NULL) {
		spin_unlock_bh(&xt_lua->lock);
		netlink_kernel_release(sock);
		return -ENOMEM;
	}

	luaU_setenv(L, xt_lua, struct xt_lua_net);
	luaL_openlibs(L);

	luaL_requiref(L, "data", luaopen_data, 1);
	lua_pop(L, 1);

	luaU_setregval(L, NFLUA_SOCK, sock);
	spin_unlock_bh(&xt_lua->lock);

	return 0;
}

static void __net_exit xt_lua_net_exit(struct net *net)
{
	struct xt_lua_net *xt_lua = xt_lua_pernet(net);
	struct sock *sock = NULL;

	spin_lock_bh(&xt_lua->lock);
	if (xt_lua->L != NULL) {
		luaU_getregval(xt_lua->L, NFLUA_SOCK, &sock);
		lua_close(xt_lua->L);
		xt_lua->L = NULL;
	}
	spin_unlock_bh(&xt_lua->lock);

	if (sock != NULL)
		netlink_kernel_release(sock);
}

static struct pernet_operations xt_lua_net_ops = {
	.init = xt_lua_net_init,
	.exit = xt_lua_net_exit,
	.id   = &xt_lua_net_id,
	.size = sizeof(struct xt_lua_net),
};

static int __init xt_lua_init(void)
{
	int ret;

	if (!nf_util_init())
		return -EFAULT;

	if ((ret = register_pernet_subsys(&xt_lua_net_ops)))
		return ret;

	if ((ret = xt_register_match(&nflua_mt_reg)))
		unregister_pernet_subsys(&xt_lua_net_ops);

	return ret;
}

static void __exit xt_lua_exit(void)
{
	xt_unregister_match(&nflua_mt_reg);
	unregister_pernet_subsys(&xt_lua_net_ops);
}

module_init(xt_lua_init);
module_exit(xt_lua_exit);
