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

#ifndef _NF_UTIL_H
#define _NF_UTIL_H

#include <linux/types.h>
#include <linux/skbuff.h>

int tcp_reply(struct sk_buff *, struct xt_action_param *,
		unsigned char *, size_t);
struct sk_buff *tcp_payload(struct sk_buff *, unsigned char *, size_t);
int tcp_send(struct sk_buff *);
int tcp_payload_length(const struct sk_buff *);
int route_me_harder(struct sk_buff *);
bool nf_util_init(void);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static inline struct net *xt_net(const struct xt_action_param *par)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	return par->net;
#else
	return dev_net((par->in != NULL) ? par->in : par->out);
#endif
}
#endif

#endif
