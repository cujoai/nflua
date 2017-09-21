/*
 * This file is Confidential Information of Cujo LLC.
 * Copyright (c) 2017 CUJO LLC. All rights reserved.
 */

#ifndef _XT_LUA_H
#define _XT_LUA_H

#include <linux/types.h>

#define XT_LUA_FUNC_SIZE	(1024)

struct xt_lua_mtinfo {
	char func[XT_LUA_FUNC_SIZE];
};

#endif
