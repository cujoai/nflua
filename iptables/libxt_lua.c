/* Copyright (C) 2017 CUJO LLC. All rights reserved */

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <xtables.h>
#include <nf_lua/xt_lua.h>

static void nflua_help(void)
{
	printf("Netfilter Lua\n"
		"[!] --function\tmatch function\n");
}

static int nflua_parse(int c, char **argv, int invert, unsigned int *flags,
			const void *entry, struct xt_entry_match **match)
{
	struct xt_lua_mtinfo *info = (struct xt_lua_mtinfo *) (*match)->data;

	switch (c) {
	case '1': /* --function */
		if (strlen(optarg) >= XT_LUA_FUNC_SIZE)
			xtables_error(PARAMETER_PROBLEM,
				"'--function' is too long (max: %zu)",
				XT_LUA_FUNC_SIZE - 1);

		strcpy(info->func, optarg);

		*flags = 1;
		break;
	}

	return 1;
}

static void nflua_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM, "'--function' is mandatory");
}

static const struct option nflua_opts[] = {
	{.name = "function", .has_arg = 1, .val = '1'},
	XT_GETOPT_TABLEEND,
};

static struct xtables_match nflua_mt_reg = {
	.version	= XTABLES_VERSION,
	.name		= "lua",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct xt_lua_mtinfo)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_lua_mtinfo)),
	.help		= nflua_help,
	.parse		= nflua_parse,
	.final_check	= nflua_check,
	.extra_opts	= nflua_opts,
};

static void _init(void)
{
	xtables_register_match(&nflua_mt_reg);
}
