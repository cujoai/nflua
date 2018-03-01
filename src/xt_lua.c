/*
 * This file is Confidential Information of Cujo LLC.
 * Copyright (c) 2017 CUJO LLC. All rights reserved.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/printk.h>

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

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <luautil.h>
#include <luadata.h>

#include "xt_lua.h"
#include "nf_util.h"

MODULE_LICENSE("Proprietary. (C) 2017 CUJO LLC.");
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

static void nflua_destroy(const struct xt_mtdtor_param *par)
{
}

static int nflua_checkentry(const struct xt_mtchk_param *par)
{
	return 0;
}

static bool nflua_match(struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_lua_mtinfo *info = par->matchinfo;
	struct nflua_ctx ctx = {.skb = skb, .par = par};
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

	frame = ldata_newref(L, skb_mac_header(skb), skb->mac_len);
	packet = ldata_newref(L, skb->data, skb->len);

	error = lua_pcall(L, 2, 1, 0);

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
		luaL_error(L, "insufficient memory");

	if ((nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, size, flags)) == NULL)
		luaL_error(L, "message too long");

	memcpy(nlmsg_data(nlh), payload, size);

	if (nlmsg_send(sock, skb, pid, group) < 0)
		luaL_error(L, "failed to send message");

	lua_pushinteger(L, (lua_Integer) size);
	return 1;
}

static const luaL_Reg nflua_lib[] = {
	{"reply", nflua_reply},
	{"netlink", nflua_netlink},
	{NULL, NULL}
};

int luaopen_nf(lua_State *L)
{
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

#define nflua_dostring(L, b, s)	\
	(luaL_loadbufferx(L, b, s, "nf_lua", "t") ||	\
	 lua_pcall(L, 0, 0, 0))


static void nflua_input(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	const char* script = (const char *) nlmsg_data(nlh);

	if (!netlink_net_capable(skb, CAP_NET_ADMIN)) {
		pr_err("operation not permitted");
		return;
	}

	spin_lock_bh(&lock);
	luaU_setenv(L, NULL, struct nflua_ctx);

	if (nflua_dostring(L, script, nlmsg_len(nlh)) != 0) {
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

	spin_lock(&lock);
	L = luaL_newstate();

	if (L == NULL)
		return -ENOMEM;

	luaL_openlibs(L);

	luaL_requiref(L, "nf", luaopen_nf, 1);
	luaL_requiref(L, "data", luaopen_data, 1);
	luaL_requiref(L, "json", luaopen_json, 1);
	luaL_requiref(L, "base64", luaopen_base64, 1);
	lua_pop(L, 4); /* nf, data, json, base64 */
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
