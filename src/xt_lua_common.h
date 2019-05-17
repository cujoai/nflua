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

#ifndef _XT_LUA_COMMON_H
#define _XT_LUA_COMMON_H

#include <linux/types.h>

#include "nfluaconf.h"

struct nflua_state;

enum {
	XT_NFLUA_TCP_PAYLOAD = 0x01
};

struct xt_lua_mtinfo {
	char name[NFLUA_NAME_MAXSIZE];
	char func[NFLUA_NAME_MAXSIZE];
	__u8 flags;

	/* kernel only */
	struct nflua_state *state  __attribute__((aligned(8)));
};

#endif /* _XT_LUA_COMMON_H */
