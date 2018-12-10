/*
 * Copyright (C) 2017-2018 CUJO LLC
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

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <xtables.h>
#include <xt_lua.h>

static void nflua_help(void)
{
	printf("Netfilter Lua\n"
		"[!] --function\tmatch function\n");
}

static int nflua_parse(int c, char **argv, int invert, unsigned int *flags,
			const void *entry, struct xt_entry_match **match)
{
	((void) argv);
	((void) invert);
	((void) flags);
	((void) entry);
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

static void
nflua_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	((void) ip);
        struct xt_lua_mtinfo *info = (struct xt_lua_mtinfo *) match->data;

        printf(" %s", info->func);
}

static void
nflua_save(const void *ip, const struct xt_entry_match *match)
{
	((void) ip);
	struct xt_lua_mtinfo *info = (struct xt_lua_mtinfo *) match->data;

	printf(" --function %s", info->func);
}

static struct xtables_match nflua_mt_reg = {
	.version	= XTABLES_VERSION,
	.name		= "lua",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.size		= XT_ALIGN(sizeof(struct xt_lua_mtinfo)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_lua_mtinfo)),
	.help		= nflua_help,
	.parse		= nflua_parse,
	.final_check	= nflua_check,
	.extra_opts	= nflua_opts,
	.save		= nflua_save,
	.print		= nflua_print,
};

static void _init(void)
{
	xtables_register_match(&nflua_mt_reg);
}
