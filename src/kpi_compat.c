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

#include <linux/kallsyms.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include "kpi_compat.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
#include "ip_forward.c"
int kpi_forward_finish_gso(struct sk_buff *skb)
{
	return ip_gso_exceeds_dst_mtu(skb) ? ip_forward_finish_gso(skb) : 0;
}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0) &&
	LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0) */

#ifdef MODULE
void (*kpi_ip_forward_options)(struct sk_buff *);

int kpi_init(void)
{
	kpi_ip_forward_options = (void(*)(struct sk_buff *))
		kallsyms_lookup_name("ip_forward_options");
	if (kpi_ip_forward_options == NULL)
		return -EFAULT;
	return 0;
}
#endif /* MODULE */
