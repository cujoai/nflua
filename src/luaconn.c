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

#include <lmemlib.h>

#include "kpi_compat.h"
#include "luautil.h"
#include "states.h"
#include "xt_lua.h"

struct nf_conn *nflua_findconnid(lua_State *L)
{
	struct nflua_state *s = luaU_getenv(L, struct nflua_state);
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *hash;
	size_t slen, dlen;
	lua_Integer family = luaL_checkinteger(L, 1);
	const char *protoname[] = {"udp", "tcp", NULL};
	const int protonums[] = {IPPROTO_UDP, IPPROTO_TCP, 0};
	int protonum = protonums[luaL_checkoption(L, 2, NULL, protoname)];
	const char *saddr = luaL_checklstring(L, 3, &slen);
	lua_Integer sport = luaL_checknumber(L, 4);
	const char *daddr = luaL_checklstring(L, 5, &dlen);
	lua_Integer dport = luaL_checknumber(L, 6);
	int (*pton)(const char *, int, u8 *, int, const char **);
	const char *end;

	memset(&tuple, 0, sizeof(tuple));

	switch (family) {
	case 4:
		tuple.src.l3num = NFPROTO_IPV4;
		pton = in4_pton;
		break;
	case 6:
		tuple.src.l3num = NFPROTO_IPV6;
		pton = in6_pton;
		break;
	default:
		return luaL_argerror(L, 1, "unknown family");
	}

	if (!pton(saddr, slen, (u8 *) tuple.src.u3.all, -1, &end))
		luaL_argerror(L, 3, "failed to convert address to binary");

	if (!pton(daddr, dlen, (u8 *) tuple.dst.u3.all, -1, &end))
		luaL_argerror(L, 5, "failed to convert address to binary");

	if (sport <= 0 || sport > USHRT_MAX)
		luaL_argerror(L, 4, "invalid port");

	if (dport <= 0 || dport > USHRT_MAX)
		luaL_argerror(L, 6, "invalid port");

	tuple.dst.protonum = protonum;
	tuple.src.u.all = htons(sport);
	tuple.dst.u.all = htons(dport);

	hash = nf_conntrack_find_get(sock_net(s->xt_lua->sock), KPI_CT_DEFAULT_ZONE, &tuple);

	if (hash == NULL)
		return NULL;

	return nf_ct_tuplehash_to_ctrack(hash);
}
EXPORT_SYMBOL(nflua_findconnid);

void nflua_getdirection(lua_State *L, int arg, int *from, int *to)
{
        static const char *const directions[] = {
                [IP_CT_DIR_ORIGINAL] = "original",
                [IP_CT_DIR_REPLY] = "reply",
                [IP_CT_DIR_MAX] = "both",
                [IP_CT_DIR_MAX + 1] = NULL
        };
        int dir = luaL_checkoption(L, arg, NULL, directions);

        if (dir == IP_CT_DIR_MAX) {
                *to = IP_CT_DIR_REPLY;
                *from = IP_CT_DIR_ORIGINAL;
        } else {
                *from = *to = dir;
        }
}
EXPORT_SYMBOL(nflua_getdirection);

static int luaconn_traffic(lua_State *L)
{
	struct nf_conn *ct;
	const char *msg = NULL;
	const struct nf_conn_counter *counters;
	int ret = 0;
	int to, from, i;

	nflua_getdirection(L, 7, &from, &to);
	if ((ct = nflua_findconnid(L)) == NULL) {
		msg = "connid entry not found";
		goto err;
	}

	if ((counters = kpi_nf_conn_acct_find(ct)) == NULL) {
		msg = "counters not found";
		goto err;
	}

	for (i = from; i <= to; i++) {
		lua_pushinteger(L, atomic64_read(&counters[i].packets));
		lua_pushinteger(L, atomic64_read(&counters[i].bytes));
		ret += 2;
	}
	goto out;
err:
	ret = 2;
	lua_pushnil(L);
	lua_pushstring(L, msg);
out:
	if (ct)
		nf_ct_put(ct);
	return ret;
}

static const luaL_Reg luaconn_lib[] = {
	{"traffic", luaconn_traffic},
	{NULL, NULL}
};

int luaopen_conn(lua_State *L)
{
	luaL_newlib(L, luaconn_lib);
	return 1;
}
EXPORT_SYMBOL(luaopen_conn);
