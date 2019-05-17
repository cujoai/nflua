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

#ifndef NFLUA_NETLINK_COMMON_H
#define NFLUA_NETLINK_COMMON_H

#include <linux/netlink.h>

#include "nfluaconf.h"

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

#define NFLUA_LIST_FRAG_SIZE \
	(NFLUA_PAYLOAD_SIZE(sizeof(struct nflua_nl_list)))

#define NFLUA_DATA_MAXSIZE \
	(NFLUA_PAYLOAD_SIZE(sizeof(struct nflua_nl_data)))

#define NFLUA_SCRIPT_MAXSIZE (NFLUA_SCRIPT_FRAG_SIZE * NFLUA_MAX_FRAGS) /* +- 64k */

#define NFLUA_LIST_MAXSIZE (NFLUA_LIST_FRAG_SIZE * NFLUA_MAX_FRAGS) /* +- 64k */

#define NFLUA_MAX_STATES (NFLUA_LIST_MAXSIZE / sizeof(struct nflua_nl_state))

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

#define NFLUA_MIN_ALLOC_BYTES (32 * 1024UL)

struct nflua_nl_state {
	char  name[NFLUA_NAME_MAXSIZE];
	__u32 maxalloc;           /* Max allocated bytes           */
	__u32 curralloc;          /* Current allocated bytes       */
};

struct nflua_nl_fragment {
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
};

struct nflua_nl_script {
	__u32 total;              /* Total number of bytes         */
	char  name[NFLUA_NAME_MAXSIZE];
	char  script[NFLUA_SCRIPTNAME_MAXSIZE];
	struct nflua_nl_fragment frag;
};

#endif /* NFLUA_NETLINK_COMMON_H */
