/*
 * This file is Confidential Information of CUJO LLC.
 * Copyright (c) 2016-2017 CUJO LLC. All rights reserved.
 */

#define LUAU_PATH      LIBEXEC_PATH "/cujo/lua"


#ifndef _LUA_UTIL_H
#define _LUA_UTIL_H

#define luaU_getudata(L, ud) \
	(lua_rawgetp(L, LUA_REGISTRYINDEX, (void *)ud) == LUA_TUSERDATA)

#define luaU_setudata(L, ud) \
	(lua_rawsetp(L, LUA_REGISTRYINDEX, (void *)ud))

#define luaU_registerudata(L, i, ud) { \
	lua_pushvalue(L, i); \
	luaU_setudata(L, ud); }

#define luaU_unregisterudata(L, ud) { \
	lua_pushnil(L); \
	luaU_setudata(L, ud); }

#define luaU_setuvalue(L, i, j) { \
	int k = i; \
	if (k < 0) \
		k--; \
	lua_pushvalue(L, j); \
	lua_setuservalue(L, k); }

#define luaU_setenv(L, env, st) { \
	st **penv = (st **)lua_getextraspace(L); \
	*penv = env; }

#define luaU_getenv(L, st)	(*((st **)lua_getextraspace(L)))

#define luaU_getuvalue(L, ud, t) \
	(luaU_getudata(L, ud) && lua_getuservalue(L, -1) == t)

#define luaU_dofile(L, f) \
	(luaL_loadfilex(L, LUAU_PATH f, "t") != 0 || \
	lua_pcall(L, 0, 0, 0) != 0)

#define luaU_setregval(L, t, v) { \
	if (v) lua_pushlightuserdata(L, v); \
	else lua_pushnil(L); \
	lua_setfield(L, LUA_REGISTRYINDEX, t); }

#define luaU_getregval(L, t, v) { \
	lua_getfield(L, LUA_REGISTRYINDEX, t); \
	*v = lua_touserdata(L, -1); \
	lua_pop(L, 1); }

#endif /* _LUA_UTIL_H */
