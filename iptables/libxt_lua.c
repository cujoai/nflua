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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <xtables.h>
#include <xt_lua.h>

enum { O_FUNCTION = 0x02, O_TCP_PAYLOAD = 0x04, O_MASK = 0x08 };

static void nflua_help(void)
{
	printf("Netfilter Lua\n"
	       "--tcp-payload\tmatch if tcp payload length is greater than zero\n"
	       "--mask mask\tmatch if any bit in mask is set by nf.set_match_bit\n"
	       "--function\tmatch function\n");
}

static int nflua_parse(int c, char **argv, int invert, unsigned int *flags,
		       const void *entry, struct xt_entry_match **match)
{
	((void)argv);
	((void)entry);
	struct xt_lua_mtinfo *info = (struct xt_lua_mtinfo *)(*match)->data;

	if (invert)
		xtables_error(PARAMETER_PROBLEM, "'!' not supported");

	switch (c) {
	case O_FUNCTION:
		if (strlen(optarg) >= XT_LUA_FUNC_SIZE)
			xtables_error(PARAMETER_PROBLEM,
				      "'--function' is too long (max: %u)",
				      XT_LUA_FUNC_SIZE - 1);

		strcpy(info->func, optarg);

		*flags |= O_FUNCTION;
		break;
	case O_TCP_PAYLOAD:
		info->flags |= XT_NFLUA_TCP_PAYLOAD;

		*flags |= O_TCP_PAYLOAD;
		break;

	case O_MASK: {
		char *end;
		unsigned long match_mask = strtoul(optarg, &end, 0);
		if (*end != '\0')
			xtables_error(PARAMETER_PROBLEM, "invalid mask '%s'",
				      optarg);
		if ((unsigned long)(__u32)match_mask != match_mask)
			xtables_error(PARAMETER_PROBLEM,
				      "mask %#lx out of range", match_mask);

		if (match_mask) {
			info->mask |= match_mask;
			*flags |= O_MASK;
		}
		break;
	}
	}

	return 1;
}

static void nflua_check(unsigned int flags)
{
	(void)flags;
}

static const struct option nflua_opts[] = {
	{ .name = "function", .has_arg = 1, .val = O_FUNCTION },
	{ .name = "tcp-payload", .has_arg = 0, .val = O_TCP_PAYLOAD },
	{ .name = "mask", .has_arg = 1, .val = O_MASK },
	XT_GETOPT_TABLEEND,
};

static void nflua_print(const void *ip, const struct xt_entry_match *match,
			int numeric)
{
	((void)ip);
	((void)numeric);
	struct xt_lua_mtinfo *info = (struct xt_lua_mtinfo *)match->data;

	/* TODO: This output order is the exact reverse of the evaluation order
	 * in the matching logic, which is misleading.
	 */

	if (info->func[0] != '\0')
		printf(" func:%s", info->func);

	if (info->flags & XT_NFLUA_TCP_PAYLOAD)
		printf(" tcp-payload");

	if (info->mask)
		printf(" mask:%#lx", (unsigned long)info->mask);
}

static void nflua_save(const void *ip, const struct xt_entry_match *match)
{
	((void)ip);
	struct xt_lua_mtinfo *info = (struct xt_lua_mtinfo *)match->data;

	/* TODO: This output order is the exact reverse of the evaluation order
	 * in the matching logic, which is misleading.
	 */

	if (info->func[0] != '\0')
		printf(" --function %s", info->func);

	if (info->flags & XT_NFLUA_TCP_PAYLOAD)
		printf(" --tcp-payload");

	if (info->mask)
		printf(" --mask %#lx", (unsigned long)info->mask);
}

static struct xtables_match nflua_mt_reg = {
	.version = XTABLES_VERSION,
	.name = "lua",
	.revision = 0,
	.family = NFPROTO_UNSPEC,
	.size = XT_ALIGN(sizeof(struct xt_lua_mtinfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_lua_mtinfo)),
	.help = nflua_help,
	.parse = nflua_parse,
	.final_check = nflua_check,
	.extra_opts = nflua_opts,
	.save = nflua_save,
	.print = nflua_print,
};

void _init(void)
{
	xtables_register_match(&nflua_mt_reg);
}
