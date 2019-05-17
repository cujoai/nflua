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

#ifndef NFLUA_NETLINK_H
#define NFLUA_NETLINK_H

#include "netlink_common.h"
#include "states.h"
#include "xt_lua.h"

int nflua_netlink_init(struct xt_lua_net *xt_lua, struct net *net);
void nflua_netlink_exit(struct xt_lua_net *xt_lua);
int nflua_rcv_nl_event(struct notifier_block *this,
				 unsigned long event, void *p);
int nflua_nl_send_data(struct nflua_state *s, u32 pid, u32 group,
		const char *payload, size_t len);

#endif /* NFLUA_NETLINK_H */
