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

#ifndef _XT_LUA_H
#define _XT_LUA_H

#include "xt_lua_common.h"
#include "luautil.h"

#define XT_LUA_HASH_BUCKETS (32)

struct sock;
struct xt_lua_net {
	struct sock *sock;
	spinlock_t client_lock;
	spinlock_t state_lock;
	spinlock_t rfcnt_lock;
	atomic_t state_count;
	struct hlist_head client_table[XT_LUA_HASH_BUCKETS];
	struct hlist_head state_table[XT_LUA_HASH_BUCKETS];
};

struct net;
struct xt_lua_net *xt_lua_pernet(struct net *net);

extern luaU_id nflua_ctx;

enum {
	NFLUA_MATCH,
	NFLUA_TARGET
};

struct nflua_ctx {
	struct sk_buff *skb;
	int hooknum;
	const struct xt_lua_mtinfo *mtinfo;
	int frame;
	int packet;
	int mode;
	struct sk_buff **lskb;
};

#endif
