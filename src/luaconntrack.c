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

#include <linux/inet.h>
#include <linux/module.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>

#include <lua.h>
#include <lauxlib.h>

#include "luaconntrack.h"
#include "luautil.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CUJO LLC <opensource@cujo.com>");
MODULE_DESCRIPTION("Lua module for conntrack utilities");

struct nf_conn *nflua_findconnid(lua_State *L)
{
	struct net *net = *luaU_getenv(L, struct net *);
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *hash;
	size_t slen, dlen;
	lua_Integer family = luaL_checkinteger(L, 1);
	const char *protoname[] = { "udp", "tcp", NULL };
	const int protonums[] = { IPPROTO_UDP, IPPROTO_TCP, 0 };
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
		serr = in4_pton(saddr, slen, (u8 *)tuple.src.u3.all, -1, &end);
		derr = in4_pton(daddr, dlen, (u8 *)tuple.dst.u3.all, -1, &end);
		break;
	case 6:
		tuple.src.l3num = NFPROTO_IPV6;
		serr = in6_pton(saddr, slen, (u8 *)tuple.src.u3.all, -1, &end);
		derr = in6_pton(daddr, dlen, (u8 *)tuple.dst.u3.all, -1, &end);
		break;
	default:
		luaL_error(L, "unknown family");
		return NULL;
	}

	if (!serr || !derr) {
		luaL_error(L, "failed to convert address to binary");
		return NULL;
	}

	tuple.dst.protonum = protonum;
	tuple.src.u.all = sport;
	tuple.dst.u.all = dport;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
	hash = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
	hash = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif

	return hash != NULL ? nf_ct_tuplehash_to_ctrack(hash) : NULL;
}
EXPORT_SYMBOL(nflua_findconnid);

void nflua_getdirection(lua_State *L, int arg, int *from, int *to)
{
	static const char *const directions[] = { [IP_CT_DIR_ORIGINAL] =
							  "original",
						  [IP_CT_DIR_REPLY] = "reply",
						  [IP_CT_DIR_MAX] = "both",
						  [IP_CT_DIR_MAX + 1] = NULL };
	int dir = luaL_checkoption(L, arg, NULL, directions);

	if (dir == IP_CT_DIR_MAX) {
		*to = IP_CT_DIR_REPLY;
		*from = IP_CT_DIR_ORIGINAL;
	} else {
		*from = *to = dir;
	}
}
EXPORT_SYMBOL(nflua_getdirection);

static int __init luaconntrack_init(void)
{
	return 0;
}

static void __exit luaconntrack_exit(void)
{
}

module_init(luaconntrack_init);
module_exit(luaconntrack_exit);
