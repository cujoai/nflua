/*
 * Copyright (C) 2017-2019  CUJO LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/version.h>

#include <linux/netfilter/x_tables.h>
#include <net/netns/generic.h>

#include <lua.h>
#include <luadata.h>

#include "xt_lua.h"
#include "nf_util.h"
#include "netlink.h"
#include "states.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pedro Caldas Tammela <pctammela@getcujo.com>");
MODULE_AUTHOR("Lourival Vieira Neto <lourival.neto@getcujo.com>");
MODULE_AUTHOR("Iruatã Souza <iru@getcujo.com>");

MODULE_DESCRIPTION("Netfilter Lua module");

luaU_id nflua_ctx;
luaU_id nflua_sock;

static int xt_lua_net_id __read_mostly;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
static inline u32 skb_mac_header_len(const struct sk_buff *skb)
{
	return skb->network_header - skb->mac_header;
}
#endif

struct xt_lua_net *xt_lua_pernet(struct net *net)
{
	return net_generic(net, xt_lua_net_id);
}

static void nflua_mt_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_lua_mtinfo *info = par->matchinfo;

	if (info->state != NULL)
		nflua_state_put(info->state);
}

static int nflua_mt_checkentry(const struct xt_mtchk_param *par)
{
	struct xt_lua_mtinfo *info = par->matchinfo;
	struct nflua_state *s;

	if ((s = nflua_state_lookup(xt_lua_pernet(par->net), info->name)) == NULL)
		return -1;

	info->state = nflua_state_get(s);
	return 0;
}

static int nflua_docall(lua_State *L)
{
	struct nflua_ctx *ctx = lua_touserdata(L, 1);
	struct sk_buff *skb = ctx->skb;
	const struct xt_lua_mtinfo *info = ctx->par->matchinfo;
	int error;

	luaU_setregval(L, nflua_ctx, ctx);

	if (lua_getglobal(L, info->func) != LUA_TFUNCTION)
		return luaL_error(L, "couldn't find function: %s\n", info->func);

	if (skb_linearize(skb) != 0)
		return luaL_error(L, "skb linearization failed.\n");

	ctx->frame = ldata_newref(L, skb_mac_header(skb), skb_mac_header_len(skb));
	ctx->packet = ldata_newref(L, skb->data, skb->len);

	error = lua_pcall(L, 2, 1, 0);

	luaU_setregval(L, nflua_ctx, NULL);
	if (ctx->lskb) luaU_unregisterudata(L, ctx->lskb);

	if (error)
		return lua_error(L);

	return 1;
}

static unsigned int string_to_tg(const char *s)
{
	struct target_pair {
		const char *k;
		int v;
	};
	static struct target_pair targets[] = {
		{"drop", NF_DROP},
		{"accept", NF_ACCEPT},
		{"stolen", NF_STOLEN},
		{"queue", NF_QUEUE},
		{"repeat", NF_REPEAT},
		{"stop", NF_STOP}
	};
	int i;

	for (i = 0; i < sizeof(targets) / sizeof(*targets); i++)
		if (strcmp(targets[i].k, s) == 0)
			return targets[i].v;

	return XT_CONTINUE;
}

union call_result {
	bool mt;
	unsigned int tg;
};

static union call_result nflua_call(struct sk_buff *skb,
    struct xt_action_param *par, int mode)
{
	const struct xt_lua_mtinfo *info = par->matchinfo;
	struct nflua_ctx ctx = {.skb = skb, .par = par,
		.frame = LUA_NOREF, .packet = LUA_NOREF,
		.mode = mode, .lskb = NULL};
	lua_State *L = info->state->L;
	union call_result r;
	int base;

	switch (mode) {
	case NFLUA_MATCH:
		r.mt = false;
		break;
	case NFLUA_TARGET:
		r.tg = XT_CONTINUE;
		break;
	}

	spin_lock(&info->state->lock);
	if (L == NULL) {
		pr_err("invalid lua state");
		goto unlock;
	}

	base = lua_gettop(L);
	lua_pushcfunction(L, nflua_docall);
	lua_pushlightuserdata(L, &ctx);

	if (luaU_pcall(L, 1, 1)) {
		pr_err("%s\n", lua_tostring(L, -1));
		goto cleanup;
	}

	switch (mode) {
	case NFLUA_MATCH:
		r.mt = lua_toboolean(L, -1);
		break;
	case NFLUA_TARGET:
		if (lua_isstring(L, -1))
			r.tg = string_to_tg(lua_tostring(L, -1));
		break;
	}

cleanup:
	if (mode == NFLUA_TARGET) {
		if (ctx.lskb)
			r.tg = NF_STOLEN;
		else if (r.tg == NF_STOLEN)
			r.tg = XT_CONTINUE;
	}

	ldata_unref(L, ctx.frame);
	ldata_unref(L, ctx.packet);
	lua_settop(L, base);
unlock:
	spin_unlock(&info->state->lock);
	return r;
}

static bool nflua_match(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_lua_mtinfo *info = par->matchinfo;

	if ((info->flags & XT_NFLUA_TCP_PAYLOAD) &&
	    tcp_payload_length(skb) <= 0)
		return false;

	return nflua_call((struct sk_buff *)skb, par, NFLUA_MATCH).mt;
}

static void nflua_tg_destroy(const struct xt_tgdtor_param *par)
{
	struct xt_lua_mtinfo *info = par->targinfo;

	if (info->state != NULL)
		nflua_state_put(info->state);
}

static int nflua_tg_checkentry(const struct xt_tgchk_param *par)
{
	struct xt_lua_mtinfo *info = par->targinfo;
	struct nflua_state *s;

	s = nflua_state_lookup(xt_lua_pernet(par->net), info->name);
	if (s == NULL)
		return -ENOENT;

	info->state = nflua_state_get(s);
	return 0;
}

static unsigned int nflua_target(struct sk_buff *skb,
		const struct xt_action_param *par)
{
	return nflua_call(skb, (struct xt_action_param *)par, NFLUA_TARGET).tg;
}

static struct xt_match nflua_mt_reg __read_mostly = {
	.name       = "lua",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = nflua_match,
	.checkentry = nflua_mt_checkentry,
	.destroy    = nflua_mt_destroy,
	.matchsize  = sizeof(struct xt_lua_mtinfo),
	.usersize   = offsetof(struct xt_lua_mtinfo, state),
	.me         = THIS_MODULE
};

static struct xt_target nflua_tg_reg __read_mostly = {
	.name       = "LUA",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.target     = nflua_target,
	.checkentry = nflua_tg_checkentry,
	.destroy    = nflua_tg_destroy,
	.targetsize = sizeof(struct xt_lua_mtinfo),
	.usersize   = offsetof(struct xt_lua_mtinfo, state),
	.me         = THIS_MODULE
};

static int __net_init xt_lua_net_init(struct net *net)
{
	struct xt_lua_net *xt_lua = xt_lua_pernet(net);

	nflua_states_init(xt_lua);

	if (nflua_netlink_init(xt_lua, net)) {
		pr_err("Netlink Socket initialization failed!\n");
		return -ENOMEM;
	}

	return 0;
}

static void __net_exit xt_lua_net_exit(struct net *net)
{
	struct xt_lua_net *xt_lua = xt_lua_pernet(net);

	nflua_netlink_exit(xt_lua);
	nflua_states_exit(xt_lua);
}

static struct pernet_operations xt_lua_net_ops = {
	.init = xt_lua_net_init,
	.exit = xt_lua_net_exit,
	.id   = &xt_lua_net_id,
	.size = sizeof(struct xt_lua_net),
};

static struct notifier_block nl_notifier = {
	.notifier_call  = nflua_rcv_nl_event,
};

static int __init xt_lua_init(void)
{
	int ret;

	pr_debug("initializing module\n");

	if (!nf_util_init())
		return -EFAULT;

	if ((ret = register_pernet_subsys(&xt_lua_net_ops)))
		return ret;

	if ((ret = netlink_register_notifier(&nl_notifier)))
		return ret;

	if ((ret = xt_register_match(&nflua_mt_reg))) {
		unregister_pernet_subsys(&xt_lua_net_ops);
		return ret;
	}

	if ((ret = xt_register_target(&nflua_tg_reg))) {
		unregister_pernet_subsys(&xt_lua_net_ops);
		xt_unregister_match(&nflua_mt_reg);
		return ret;
	}

	return ret;
}

static void __exit xt_lua_exit(void)
{
	pr_debug("unloading module\n");
	xt_unregister_match(&nflua_mt_reg);
	xt_unregister_target(&nflua_tg_reg);
	unregister_pernet_subsys(&xt_lua_net_ops);
	netlink_unregister_notifier(&nl_notifier);
}

module_init(xt_lua_init);
module_exit(xt_lua_exit);
