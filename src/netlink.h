/*
 * Copyright (C) 2017-2019 CUJO LLC
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

#ifndef NFLUA_NETLINK_H
#define NFLUA_NETLINK_H

#include <linux/netlink.h>

#if PAGE_SIZE < 8192UL
#define NFLUA_PAYLOAD_MAXSIZE PAGE_SIZE
#define NFLUA_MAX_FRAGS       16
#else
#define NFLUA_PAYLOAD_MAXSIZE 8192UL
#define NFLUA_MAX_FRAGS       8
#endif

#define NFLUA_PAYLOAD_SIZE(x) (NFLUA_PAYLOAD_MAXSIZE - NLMSG_SPACE(x))

#define NFLUA_SCRIPT_FRAG_SIZE \
	(NFLUA_PAYLOAD_SIZE(sizeof(struct nflua_nl_script)))

#define NFLUA_DATA_FRAG_SIZE \
	(NFLUA_PAYLOAD_SIZE(sizeof(struct nflua_nl_data)))

#define NFLUA_LIST_FRAG_SIZE \
	(NFLUA_PAYLOAD_SIZE(sizeof(struct nflua_nl_list)))

#define NFLUA_SCRIPT_MAXSIZE (NFLUA_SCRIPT_FRAG_SIZE * NFLUA_MAX_FRAGS) /* +- 64k */

#define NFLUA_DATA_MAXSIZE (NFLUA_DATA_FRAG_SIZE * NFLUA_MAX_FRAGS) /* +- 64k */

#define NFLUA_LIST_MAXSIZE (NFLUA_LIST_FRAG_SIZE * NFLUA_MAX_FRAGS) /* +- 64k */

#define NETLINK_NFLUA      31     /* NFLua netlink protocol family */

#define NFLUA_MAX_STATES (NFLUA_LIST_MAXSIZE / sizeof(struct nflua_nl_state))

#define NFLUA_NAME_MAXSIZE 64     /* Max length of Lua state name  */

#define NFLUA_SCRIPTNAME_MAXSIZE 255   /* Max length of Lua state name  */

/* NFLua netlink message types */
enum {
	NFLMSG_CREATE = 16,       /* NFLua create state msg type   */
	NFLMSG_DESTROY,           /* NFLua destroy state msg type  */
	NFLMSG_LIST,              /* NFLua list states msg type    */
	NFLMSG_EXECUTE,           /* NFLua execute states msg type */
	NFLMSG_DATA               /* NFLua data                    */
};

/* NFLua netlink header flags */
#define NFLM_F_REQUEST	0x01	  /* A request message             */
#define NFLM_F_MULTI	0x02	  /* Multipart message             */
#define NFLM_F_DONE		0x04	  /* Last message                  */
#define NFLM_F_INIT		0x08	  /* First message                 */

struct nflua_nl_state {
	char  name[NFLUA_NAME_MAXSIZE];
	__u16 maxalloc;           /* Max alloc kbytes              */
};

struct nflua_nl_fragment {
	__s32 stateid;            /* State Id                      */
	__u32 seq;                /* Current frament number        */
	__u32 offset;             /* Current number of items sent  */
};

struct nflua_nl_list {
	__u32 total;              /* Total number of items         */
	struct nflua_nl_fragment frag;
};

struct nflua_nl_destroy {
	char  name[NFLUA_NAME_MAXSIZE];
};

struct nflua_nl_data {
	__u32 total;              /* Total number of bytes         */
	char  name[NFLUA_NAME_MAXSIZE];
	struct nflua_nl_fragment frag;
};

struct nflua_nl_script {
	__u32 total;              /* Total number of bytes         */
	char  name[NFLUA_NAME_MAXSIZE];
	char  script[NFLUA_SCRIPTNAME_MAXSIZE];
	struct nflua_nl_fragment frag;
};

#if defined(__KERNEL__)
#include "states.h"
#include "xt_lua.h"

int nflua_netlink_init(struct xt_lua_net *xt_lua, struct net *net);
void nflua_netlink_exit(struct xt_lua_net *xt_lua);
int nflua_rcv_nl_event(struct notifier_block *this,
				 unsigned long event, void *p);
int nflua_nl_send_data(struct nflua_state *s, u32 pid, u32 group,
		const char *payload, size_t len);
#endif /* __KERNEL__ */

#endif /* NFLUA_NETLINK_H */
