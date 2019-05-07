/*
 * Copyright (C) 2017-2018  CUJO LLC
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
#include <linux/netfilter/x_tables.h>

int tcp_reply(struct sk_buff *, int, unsigned char *, size_t);
struct sk_buff *tcp_payload(struct sk_buff *, unsigned char *, size_t);
int tcp_send(struct sk_buff *);
int tcp_payload_length(const struct sk_buff *);
int route_me_harder(struct sk_buff *);
bool nf_util_init(void);

#endif /* _NF_UTIL_H */
