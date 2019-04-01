/*
 * Copyright (C) 2018-2019  CUJO LLC
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
#include <linux/export.h>
#include <linux/timer.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "states.h"
#include "luautil.h"
#include "kpi_compat.h"

#define NFLUA_TIMER "ltimer"

struct nftimer_ctx {
	struct timer_list timer;
	struct nflua_state *state;
};

static void timeout_cb(kpi_timer_list_t l)
{
	struct nftimer_ctx *ctx = kpi_from_timer(ctx, l, timer);
	int base;

	spin_lock(&ctx->state->lock);
	if (ctx->state->L == NULL) {
		pr_err("invalid lua state");
		goto unlock;
	}
	base = lua_gettop(ctx->state->L);

	/* check if ltimer_destroy was called for this timer */
	if (!luaU_pushudata(ctx->state->L, ctx)) goto cleanup;

	lua_getuservalue(ctx->state->L, -1);
	if (lua_pcall(ctx->state->L, 0, 0, 0) != 0) {
		pr_warn("%s", lua_tostring(ctx->state->L, -1));
		goto cleanup;
	}

cleanup:
	luaU_unregisterudata(ctx->state->L, ctx);
	lua_settop(ctx->state->L, base);
unlock:
	spin_unlock(&ctx->state->lock);
}

static int ltimer_create(lua_State *L)
{
	struct nftimer_ctx *ctx;
	unsigned long msecs = luaL_checkinteger(L, 1);

	luaL_checktype(L, 2, LUA_TFUNCTION);

	ctx = lua_newuserdata(L, sizeof(struct nftimer_ctx));
	ctx->state = luaU_getenv(L, struct nflua_state);
	luaL_setmetatable(L, NFLUA_TIMER);

	kpi_timer_setup(&ctx->timer, timeout_cb, ctx);
	if (mod_timer(&ctx->timer, jiffies + msecs_to_jiffies(msecs)))
		return luaL_error(L, "error setting timer");

	lua_pushvalue(L, 2);
	lua_setuservalue(L, -2);

	luaU_registerudata(L, -1);

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
