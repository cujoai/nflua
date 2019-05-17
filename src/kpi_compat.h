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

#ifndef _KPI_COMPAT_H
#define _KPI_COMPAT_H

#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/module.h>
#include <net/netfilter/nf_conntrack_zones.h>

#include "nfluaconf.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
#define KPI_CT_DEFAULT_ZONE	NF_CT_DEFAULT_ZONE
#else
#define KPI_CT_DEFAULT_ZONE	&nf_ct_zone_dflt
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
#define kpi_netlink_kernel_create		netlink_kernel_create
typedef struct netlink_kernel_cfg kpi_netlink_kernel_cfg;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
#define kpi_netlink_kernel_create(net, prot, c) \
	netlink_kernel_create(net, prot, THIS_MODULE, c)
typedef struct netlink_kernel_cfg kpi_netlink_kernel_cfg;
#else
#define kpi_netlink_kernel_create(net, prot, c) \
        netlink_kernel_create(net, prot, (c)->groups, (c)->input, NULL, THIS_MODULE)
typedef struct {
	unsigned int groups;
	void (*input)(struct sk_buff *skb);
} kpi_netlink_kernel_cfg;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
#define kpi_netlink_notify_portid(n)	(n)->portid
#else
#define kpi_netlink_notify_portid(n)	(n)->pid
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#define kpi_ns_capable			ns_capable
#else
#define kpi_ns_capable(ns, cap)		capable(cap)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
#define kpi_ip6_flow_hdr		ip6_flow_hdr
#define kpi_hlist_for_each_entry_rcu	hlist_for_each_entry_rcu
#define	kpi_hlist_for_each_entry_safe	hlist_for_each_entry_safe
#else
#define kpi_ip6_flow_hdr(hdr, tclass, flowlabel) \
	{*(__be32 *)(hdr) = ntohl(0x60000000 | ((tclass) << 20)) | (flowlabel);}

#define kpi_hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

#define kpi_hlist_for_each_entry_rcu(pos, head, member)			\
	for (pos = kpi_hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = kpi_hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))

#define kpi_hlist_for_each_entry_safe(pos, n, head, member) 		\
	for (pos = kpi_hlist_entry_safe((head)->first, typeof(*pos), member);\
	     pos && ({ n = pos->member.next; 1; });			\
	     pos = kpi_hlist_entry_safe(n, typeof(*pos), member))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0) || \
	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#define kpi_forward_finish_gso(skb)		0
#else
int kpi_forward_finish_gso(struct sk_buff *skb);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
#define kpi_dst_output			dst_output
#define kpi_ip_local_out		ip_local_out
#define kpi_ip6_local_out		ip6_local_out
#define kpi_ip_route_me_harder		ip_route_me_harder
#define kpi_ip6_route_me_harder		ip6_route_me_harder
#else
#define kpi_dst_output(net, sk, skb)		dst_output(skb)
#define kpi_ip_local_out(net, sk, skb)		ip_local_out(skb)
#define kpi_ip6_local_out(net, sk, skb)		ip6_local_out(skb)
#define kpi_ip_route_me_harder(net, skb, a)	ip_route_me_harder(skb, a)
#define kpi_ip6_route_me_harder(net, skb)	ip6_route_me_harder(skb)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
#define KPI_IP_INC_STATS	__IP_INC_STATS
#define KPI_IP_ADD_STATS	__IP_ADD_STATS
#define KPI_IP6_INC_STATS	__IP6_INC_STATS
#define KPI_IP6_ADD_STATS	__IP6_ADD_STATS
#else
#define KPI_IP_INC_STATS  	IP_INC_STATS_BH
#define KPI_IP_ADD_STATS  	IP_ADD_STATS_BH
#define KPI_IP6_INC_STATS	IP6_INC_STATS_BH
#define KPI_IP6_ADD_STATS	IP6_ADD_STATS_BH
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
#define kpi_full_name_hash		full_name_hash
#else
#define kpi_full_name_hash(salt, s, l)	full_name_hash(s, l)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
#define kpi_xt_hooknum		xt_hooknum
#else
#define kpi_xt_hooknum(par)	par->hooknum
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#define kpi_get_random_u32	get_random_u32
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#define kpi_get_random_u32	prandom_u32
#else
#define kpi_get_random_u32	random32
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/refcount.h>
typedef refcount_t kpi_refcount_t;
#define kpi_refcount_read	refcount_read
#define kpi_refcount_inc	refcount_inc
#define kpi_refcount_dec	refcount_dec
#define KPI_XT_MATCH_USERSIZE	1
#else
#include <linux/atomic.h>
typedef atomic_t kpi_refcount_t;
#define kpi_refcount_read	atomic_read
#define kpi_refcount_inc	atomic_inc
#define kpi_refcount_dec	atomic_dec
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
#define kpi_skb_mac_header_len		skb_mac_header_len
#define kpi_skb_users(skb)		refcount_read(&(skb)->users)
#else
#define kpi_skb_mac_header_len(skb) \
	((skb)->network_header - (skb)->mac_header)
#define kpi_skb_users(skb)		atomic_read(&(skb)->users)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
#define kpi_timer_setup(timer, cb, ctx)		timer_setup(timer, cb, 0)
#define kpi_from_timer				from_timer
typedef struct timer_list *kpi_timer_list_t;
#else
#define kpi_timer_setup(timer, cb, ctx) \
	setup_timer(timer, cb, (unsigned long)(ctx))
#define kpi_from_timer(var, data, _)		(typeof(var))(data)
typedef unsigned long kpi_timer_list_t;
#endif

#ifndef kpi_nlmsg_unicast
#define kpi_nlmsg_unicast			nlmsg_unicast
#endif

#ifndef MODULE
#define kpi_ip_forward_options			ip_forward_options
#define kpi_init()				0
#else
extern void (*kpi_ip_forward_options)(struct sk_buff *);
int kpi_init(void);
#endif

#endif /* _KPI_COMPAT_H */
