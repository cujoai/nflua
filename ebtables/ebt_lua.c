/*
 * This file is Confidential Information of Cujo LLC.
 * Copyright (c) 2018 CUJO LLC. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <xt_lua.h>
#include "../include/ebtables_u.h"

static void nflua_help(void)
{
	printf("Netfilter Lua\n"
		"[!] --function\tmatch function\n");
}

static int nflua_parse(int c, char **argv, int argc, const struct ebt_u_entry *entry,
			unsigned int *flags, struct ebt_entry_match **match)
{
	(void) argv;
	(void) flags;
	(void) entry;
	struct xt_lua_mtinfo *info = (struct xt_lua_mtinfo *) (*match)->data;

	switch (c) {
	case XT_LUA_FUNC_ARG: /* --function */
		if (strlen(optarg) >= XT_LUA_FUNC_SIZE)
			ebt_print_error("'--function' is too long (max: %zu)",
				XT_LUA_FUNC_SIZE - 1);

		strcpy(info->func, optarg);
		info->bitmask |= XT_LUA_FUNC_ARG;
		break;
	default:
		return 0;
	}

	return 1;
}

static const struct option nflua_opts[] = {
	{"function", required_argument, 0, XT_LUA_FUNC_ARG},
	{0}
};

static void
nflua_print(const struct ebt_u_entry *ip, const struct ebt_entry_match *match)
{
	struct xt_lua_mtinfo *info = (struct xt_lua_mtinfo *) match->data;
	printf(" %s", info->func);
}

static void nflua_init(struct ebt_entry_match *match) {
	struct xt_lua_mtinfo *info = (struct xt_lua_mtinfo *) match->data;
	info->bitmask = 0;
}

static void nflua_final_check(const struct ebt_u_entry *entry, const struct
		ebt_entry_match *match, const char *name,
		unsigned int hookmask, unsigned int time) {

	struct xt_lua_mtinfo *info = (struct xt_lua_mtinfo *) match->data;
	if (!(info->bitmask & XT_LUA_FUNC_ARG))
		ebt_print_error("argument --function is mandatory");

	if ((entry->ethproto != ETH_P_IP || entry->invflags & EBT_IPROTO) && (entry->ethproto != ETH_P_IPV6)) {
			ebt_print_error("For IP filtering the protocol must be "
						"specified as IPv4 or IPv6");
	}
}

static int nflua_compare(const struct ebt_entry_match *m1,
   const struct ebt_entry_match *m2)
{
	struct xt_lua_mtinfo *info1 = (struct xt_lua_mtinfo *)m1->data;
	struct xt_lua_mtinfo *info2 = (struct xt_lua_mtinfo *)m2->data;

	if (info1->bitmask != info2->bitmask)
		return 0;

	if (strcmp(info1->func, info2->func))
		return 0;

	return 1;
}

static struct ebt_u_match nflua_mt_reg = {
	.name		= "lua",
	.size		= sizeof(struct xt_lua_mtinfo),
	.help		= nflua_help,
	.parse		= nflua_parse,
	.extra_ops	= nflua_opts,
	.print		= nflua_print,
	.init		= nflua_init,
	.final_check	= nflua_final_check,
	.compare	= nflua_compare,
};

__attribute__((constructor)) static void extension_init(void)
{
	ebt_register_match(&nflua_mt_reg);
}
