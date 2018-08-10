/*
 * This file is Confidential Information of Cujo LLC.
 * Copyright (c) 2018 CUJO LLC. All rights reserved.
 */

#include <linux/printk.h>
#include <linux/timer.h>
#include <linux/hardirq.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "luautil.h"

struct context {
	struct timer_list timer;
	lua_State *L;
};

static void timeout_cb(unsigned long data)
{
	struct context *ctx = (struct context *)data;
	lua_State *L = ctx->L;
	int base = lua_gettop(L);

	/*
	 * if we have already called ltimer_destroy for this timer,
	 * the lua callback is going to be nil, so we just bail out.
	 */
	if (!luaU_getuvalue(L, ctx, LUA_TFUNCTION))
		goto out;

	if (lua_pcall(L, 0, 0, 0) != 0) {
		pr_warn("%s", lua_tostring(L, -1));
		goto out;
	}

out:
	luaU_unregisterudata(L, ctx);
	lua_settop(L, base);
}

static int ltimer_create(lua_State *L)
{
	struct context *ctx = lua_newuserdata(L, sizeof(struct context));
	unsigned long msecs = luaL_checkinteger(L, 1);

	luaL_checktype(L, 2, LUA_TFUNCTION);

	ctx->L = L;

	setup_timer(&ctx->timer, timeout_cb, (unsigned long)ctx);
	if (mod_timer(&ctx->timer, jiffies + msecs_to_jiffies(msecs)))
		return luaL_error(L, "error setting timer");

	luaU_registerudata(L, -1, ctx); /* shouldn't gc context */
	luaU_setuvalue(L, -1, 2); /* store callback */

	return 1;
}

static int ltimer_destroy(lua_State *L)
{
	struct context *ctx = lua_touserdata(L, 1);
	int base = lua_gettop(L);

	/* the timer callback has already cleaned the context up */
	if (ctx == NULL)
		return 0;

	del_timer(&ctx->timer);

	luaU_unregisterudata(L, ctx);
	lua_settop(L, base);
	return 0;
}

/* functions for 'timer' library */
static const luaL_Reg timerlib[] = {
	{"create", ltimer_create},
	{"destroy", ltimer_destroy},
	{NULL, NULL}
};

int luaopen_timer(lua_State *L)
{
	luaL_newlib(L, timerlib);
	return 1;
}
