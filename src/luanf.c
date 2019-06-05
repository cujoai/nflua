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
#include <linux/inet.h>
#include <linux/export.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <lmemlib.h>

#include "luautil.h"
#include "xt_lua.h"
#include "netlink.h"
#include "states.h"
#include "nf_util.h"
#include "kpi_compat.h"

static int nflua_reply(lua_State *L)
{
	size_t len;
	unsigned char *type;
	unsigned char *msg;
	struct nflua_ctx *ctx;

	ctx = luaU_getregval(L, nflua_ctx);
	if (ctx == NULL)
		goto error;

	type = (unsigned char *)luaL_checkstring(L, 1);
	msg = (unsigned char *)luaL_checklstring(L, 2, &len);

	switch (type[0]) {
	case 't':
		if (tcp_reply(ctx->skb, ctx->hooknum, msg, len) != 0)
			goto error;
		break;
	default:
		goto error;
	}

	return 0;
error:
	return luaL_error(L, "couldn't reply a packet");
}

static int nflua_netlink(lua_State *L)
{
	struct nflua_state *s = luaU_getenv(L, struct nflua_state);
	int pid = luaL_checkinteger(L, 1);
	int group = luaL_optinteger(L, 2, 0);
	const char *payload;
	size_t size;
	int err;

	if (s == NULL)
		return luaL_error(L, "invalid nflua_state");

	payload = luamem_checkstring(L, 3, &size);

	if ((err = nflua_nl_send_data(s, pid, group, payload, size)) < 0)
		return luaL_error(L, "failed to send message. Return code %d", err);

	lua_pushinteger(L, (lua_Integer)size);
	return 1;
}

static int nflua_skb_send(lua_State *L)
{
	struct sk_buff *nskb, **lskb = luaL_checkudata(L, 1, "nflua.packet");
	unsigned char *payload;
	size_t len;

	if (*lskb == NULL)
		return luaL_error(L, "closed packet");

	payload = (unsigned char *)lua_tolstring(L, 2, &len);
	if (payload != NULL) {
		nskb = tcp_payload(*lskb, payload, len);
		if (nskb == NULL)
			return luaL_error(L, "unable to set tcp payload");

		/* Original packet is not needed anymore */
		kfree_skb(*lskb);
	} else {
		if (unlikely(skb_shared(*lskb)))
			return luaL_error(L, "cannot send a shared skb");
		nskb = *lskb;
	}
	*lskb = NULL;

	if (route_me_harder(nskb)) {
		kfree_skb(nskb);
		luaL_error(L, "unable to route packet");
	}

	if (tcp_send(nskb))
		luaL_error(L, "unable to send packet");

	return 0;
}

static int nflua_getpacket(lua_State *L)
{
	struct nflua_ctx *ctx;

	ctx = luaU_getregval(L, nflua_ctx);
	if (ctx == NULL)
		return luaL_error(L, "couldn't get packet context");

	if (ctx->mode != NFLUA_TARGET)
		return luaL_error(L, "not on target context");

	if (ctx->lskb)
		luaU_pushudata(L, ctx->lskb);
	else {
		ctx->lskb = lua_newuserdata(L, sizeof(struct sk_buff *));
		*ctx->lskb = ctx->skb;
		luaL_setmetatable(L, "nflua.packet");
		luaU_registerudata(L, -1);
	}

	return 1;
}

static int nflua_skb_free(lua_State *L)
{
	struct sk_buff **lskb = luaL_checkudata(L, 1, "nflua.packet");

	if (*lskb != NULL) {
		kfree_skb(*lskb);
		*lskb = NULL;
	}

	return 0;
}

static int nflua_skb_tostring(lua_State *L)
{
	struct sk_buff **lskb = luaL_checkudata(L, 1, "nflua.packet");
	struct sk_buff *skb = *lskb;

	if (skb == NULL) {
		lua_pushliteral(L, "packet closed");
	} else {
		lua_pushfstring(L,
			"packet: { len:%d data_len:%d users:%d "
			"cloned:%d dataref:%d frags:%d }",
			skb->len,
			skb->data_len,
			kpi_skb_users(skb),
			skb->cloned,
			atomic_read(&skb_shinfo(skb)->dataref),
			skb_shinfo(skb)->nr_frags);
	}

	return 1;
}

int nflua_connid(lua_State *L)
{
	struct nflua_ctx *ctx;
	enum ip_conntrack_info info;
	struct nf_conn *conn;

	ctx = luaU_getregval(L, nflua_ctx);
	if (ctx == NULL)
		return luaL_error(L, "couldn't get packet context");

	conn = nf_ct_get(ctx->skb, &info);
	lua_pushlightuserdata(L, conn);

	return 1;
}

static int nflua_findconnid(lua_State *L)
{
	struct nflua_state *s = luaU_getenv(L, struct nflua_state);
	struct nf_conn *conn;
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *hash;
	size_t slen, dlen;
	lua_Integer family = luaL_checkinteger(L, 1);
	const char *protoname[] = {"udp", "tcp", NULL};
	const int protonums[] = {IPPROTO_UDP, IPPROTO_TCP, 0};
	int protonum = protonums[luaL_checkoption(L, 2, NULL, protoname)];
	const char *saddr = luaL_checklstring(L, 3, &slen);
	__be16 sport = htons(luaL_checknumber(L, 4));
	const char *daddr = luaL_checklstring(L, 5, &dlen);
	__be16 dport = htons(luaL_checknumber(L, 6));
	int derr, serr;
	const char *end;

	memset(&tuple, 0, sizeof(tuple));

	switch (family) {
	case 4:
		tuple.src.l3num = NFPROTO_IPV4;
		serr = in4_pton(saddr, slen, (u8 *) tuple.src.u3.all, -1, &end);
		derr = in4_pton(daddr, dlen, (u8 *) tuple.dst.u3.all, -1, &end);
		break;
	case 6:
		tuple.src.l3num = NFPROTO_IPV6;
		serr = in6_pton(saddr, slen, (u8 *) tuple.src.u3.all, -1, &end);
		derr = in6_pton(daddr, dlen, (u8 *) tuple.dst.u3.all, -1, &end);
		break;
	default:
		return luaL_error(L, "unknown family");
	}

	if (!serr || !derr)
		return luaL_error(L, "failed to convert address to binary");

	tuple.dst.protonum = protonum;
	tuple.src.u.all = sport;
	tuple.dst.u.all = dport;

	hash = nf_conntrack_find_get(sock_net(s->xt_lua->sock), KPI_CT_DEFAULT_ZONE, &tuple);

	if (hash == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "connid entry not found");
		return 2;
	}

	conn = nf_ct_tuplehash_to_ctrack(hash);
	lua_pushlightuserdata(L, conn);

	return 1;
}

static int nflua_traffic(lua_State *L)
{
	static const char *const directions[] = {
		[IP_CT_DIR_ORIGINAL] = "original",
		[IP_CT_DIR_REPLY] = "reply",
		[IP_CT_DIR_MAX] = NULL
	};
	struct nf_conn *ct = lua_touserdata(L, 1);
	int dir = luaL_checkoption(L, 2, NULL, directions);
	const struct nf_conn_counter *counters;

	luaL_argcheck(L, ct != NULL, 1, "invalid connid");

	if ((counters = kpi_nf_conn_acct_find(ct)) == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "counters not found");
		return 2;
	}

	lua_pushinteger(L, atomic64_read(&counters[dir].packets));
	lua_pushinteger(L, atomic64_read(&counters[dir].bytes));

	return 2;
}

static const luaL_Reg nflua_lib[] = {
	{"reply", nflua_reply},
	{"netlink", nflua_netlink},
	{"getpacket", nflua_getpacket},
	{"connid", nflua_connid},
	{"findconnid", nflua_findconnid},
	{"traffic", nflua_traffic},
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
	luaL_newmetatable(L, "nflua.packet");
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, nflua_skb_ops, 0);
	lua_pop(L, 1);

	luaL_newlib(L, nflua_lib);
	return 1;
}
EXPORT_SYMBOL(luaopen_nf);
