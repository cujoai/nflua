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

#ifndef _XT_LUA_H
#define _XT_LUA_H

#include <linux/types.h>

#define XT_LUA_STATENAME_SIZE	(64)
#define XT_LUA_FUNCNAME_SIZE	(64)

struct nflua_state;

enum {
	XT_NFLUA_TCP_PAYLOAD = 0x01
};

struct xt_lua_mtinfo {
	char name[XT_LUA_STATENAME_SIZE];
	char func[XT_LUA_FUNCNAME_SIZE];
	__u8 flags;

	/* kernel only */
	struct nflua_state *state  __attribute__((aligned(8)));
};

#if defined(__KERNEL__)
#include <linux/idr.h>

#define XT_LUA_HASH_BUCKETS (32)

struct sock;
struct xt_lua_net {
	struct sock *sock;
	spinlock_t client_lock;
	spinlock_t state_lock;
	struct ida ida;
	struct hlist_head client_table[XT_LUA_HASH_BUCKETS];
	struct hlist_head state_table[XT_LUA_HASH_BUCKETS];
};

struct net;
struct xt_lua_net *xt_lua_pernet(struct net *net);

#define NFLUA_CTXENTRY "nflua_ctx"

enum {
	NFLUA_MATCH,
	NFLUA_TARGET
};

struct nflua_ctx {
	struct sk_buff *skb;
	struct xt_action_param *par;
	int frame;
	int packet;
	int mode;
	struct sk_buff **lskb;
};
#endif /* __KERNEL__ */

#endif
