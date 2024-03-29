/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2003 USAGI/WIDE Project, Yasuyuki Kozakai <yasuyuki.kozakai@toshiba.co.jp>
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2005-2007 Patrick McHardy <kaber@trash.net>
 * (C) 2017-2019 This file was modified by CUJO LLC
 *
 * Based on net/ipv4/ip_forward.c, net/ipv6/ip6_output.c, net/ipv6.h,
 * linux/net.h
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/inetdevice.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include "nf_util.h"

/*
 * IPv6 support in nf_util is not
 * adapted to older kernels.
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
#if IS_ENABLED(CONFIG_IPV6)
#define USE_IPV6
#define DEFAULT_TOS_VALUE 0x0U
#endif
#elif defined(CONFIG_IPV6)
#define USE_IPV6
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#define __dst_output(skb) (dst_output(dev_net(skb_dst(skb)->dev), skb->sk, skb))
#else
#define __dst_output(skb) (dst_output(skb))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
#define __IP_INC_STATS IP_INC_STATS_BH
#define __IP_ADD_STATS IP_ADD_STATS_BH
#ifdef USE_IPV6
#define __IP6_INC_STATS IP6_INC_STATS_BH
#define __IP6_ADD_STATS IP6_ADD_STATS_BH
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
#define net_dbg_ratelimited(fmt, ...)                 \
	do {                                          \
		if (net_ratelimit())                  \
			pr_debug(fmt, ##__VA_ARGS__); \
	} while (0)
#endif

static int route_me_harder4(struct net *net, struct sk_buff *skb);

#ifdef USE_IPV6
static int route_me_harder6(struct net *net, struct sk_buff *skb);

#include <net/ip6_route.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
static inline void ip6_flow_hdr(struct ipv6hdr *hdr, unsigned int tclass,
				__be32 flowlabel)
{
	*(__be32 *)hdr = ntohl(0x60000000 | (tclass << 20)) | flowlabel;
}
#endif

// 5.11 mainline, backported to 5.10.121
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 121)
#define flowi6_to_flowi_common(f) flowi6_to_flowi(f)
#endif

static int tcp_ipv6_reply(struct sk_buff *oldskb, struct xt_action_param *par,
			  unsigned char *msg, size_t len)
{
	struct net *net = xt_net(par);
	struct sk_buff *nskb;
	struct tcphdr otcph, *tcph;
	unsigned int otcplen, hh_len;
	unsigned char *data;
	size_t tcplen;
	int tcphoff, hook;
	const struct ipv6hdr *oip6h = ipv6_hdr(oldskb);
	struct ipv6hdr *ip6h;
	const __u8 tclass = DEFAULT_TOS_VALUE;
	struct dst_entry *dst = NULL;
	u8 proto;
	__be16 frag_off;
	struct flowi6 fl6;

	if ((!(ipv6_addr_type(&oip6h->saddr) & IPV6_ADDR_UNICAST)) ||
	    (!(ipv6_addr_type(&oip6h->daddr) & IPV6_ADDR_UNICAST))) {
		pr_warn("addr is not unicast.\n");
		return -1;
	}

	proto = oip6h->nexthdr;
	tcphoff = ipv6_skip_exthdr(oldskb, ((u8 *)(oip6h + 1) - oldskb->data),
				   &proto, &frag_off);

	if ((tcphoff < 0) || (tcphoff > oldskb->len)) {
		pr_warn("Cannot get TCP header.\n");
		return -1;
	}

	otcplen = oldskb->len - tcphoff;

	/* IP header checks: fragment, too short. */
	if (proto != IPPROTO_TCP || otcplen < sizeof(struct tcphdr)) {
		pr_warn("proto(%d) != IPPROTO_TCP, "
			"or too short. otcplen = %d\n",
			proto, otcplen);
		return -1;
	}

	if (skb_copy_bits(oldskb, tcphoff, &otcph, sizeof(struct tcphdr)))
		BUG();

	/* No reply for RST. */
	if (otcph.rst) {
		pr_warn("RST is set\n");
		return -1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	hook = xt_hooknum(par);
#else
	hook = par->hooknum;
#endif

	/* Check checksum. */
	if (nf_ip6_checksum(oldskb, hook, tcphoff, IPPROTO_TCP)) {
		pr_warn("TCP checksum is invalid\n");
		return -1;
	}

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_TCP;
	fl6.saddr = oip6h->daddr;
	fl6.daddr = oip6h->saddr;
	fl6.fl6_sport = otcph.dest;
	fl6.fl6_dport = otcph.source;
	security_skb_classify_flow(oldskb, flowi6_to_flowi_common(&fl6));
	dst = ip6_route_output(net, NULL, &fl6);
	if (dst == NULL || dst->error) {
		dst_release(dst);
		return -1;
	}
	dst = xfrm_lookup(net, dst, flowi6_to_flowi(&fl6), NULL, 0);
	if (IS_ERR(dst)) {
		return -1;
	}

	hh_len = (dst->dev->hard_header_len + 15) & ~15;
	nskb = alloc_skb(hh_len + 15 + dst->header_len +
				 sizeof(struct ipv6hdr) +
				 sizeof(struct tcphdr) + dst->trailer_len + len,
			 GFP_ATOMIC);

	if (!nskb) {
		pr_warn("cannot alloc new skb\n");
		dst_release(dst);
		return -1;
	}

	skb_dst_set(nskb, dst);

	skb_reserve(nskb, hh_len + dst->header_len);

	skb_put(nskb, sizeof(struct ipv6hdr));
	skb_reset_network_header(nskb);
	ip6h = ipv6_hdr(nskb);
	ip6_flow_hdr(ip6h, tclass, 0);
	ip6h->hop_limit = ip6_dst_hoplimit(dst);
	ip6h->nexthdr = IPPROTO_TCP;
	ip6h->saddr = oip6h->daddr;
	ip6h->daddr = oip6h->saddr;

	skb_reset_transport_header(nskb);
	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	/* Truncate to length */
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->source = otcph.dest;
	tcph->dest = otcph.source;

	tcph->seq = otcph.ack_seq;
	tcph->ack_seq = htonl(ntohl(otcph.seq) + otcph.syn + otcph.fin +
			      otcplen - (otcph.doff << 2));

	((u_int8_t *)tcph)[13] = 0;
	tcph->psh = 1;
	tcph->ack = 1;
	tcph->window = 0;
	tcph->urg_ptr = 0;
	tcph->check = 0;

	data = skb_put(nskb, len);
	memcpy(data, msg, len);

	tcplen = nskb->len - sizeof(struct ipv6hdr);
	/* Adjust TCP checksum */
	tcph->check = csum_ipv6_magic(&ipv6_hdr(nskb)->saddr,
				      &ipv6_hdr(nskb)->daddr, tcplen,
				      IPPROTO_TCP,
				      csum_partial(tcph, tcplen, 0));
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	nf_ct_attach(nskb, oldskb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	ip6_local_out(xt_net(par), nskb->sk, nskb);
#else
	ip6_local_out(nskb);
#endif

	return 0;
}

static struct sk_buff *tcp_ipv6_payload(struct sk_buff *skb,
					unsigned char *payload, size_t len)
{
	struct tcphdr tcph, *ntcphp;
	struct ipv6hdr *nip6h, *ip6h = ipv6_hdr(skb);
	struct sk_buff *nskb;
	unsigned char *data;
	unsigned int otcplen;
	size_t tcplen;
	int tcphoff;
	u8 proto;
	__be16 frag_off;

	if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST) ||
	    !(ipv6_addr_type(&ip6h->daddr) & IPV6_ADDR_UNICAST)) {
		pr_warn("addr is not unicast.\n");
		return NULL;
	}

	proto = ip6h->nexthdr;
	tcphoff = ipv6_skip_exthdr(skb, (u8 *)(ip6h + 1) - skb->data, &proto,
				   &frag_off);

	if (tcphoff < 0 || tcphoff > skb->len) {
		pr_warn("Cannot get TCP header.\n");
		return NULL;
	}

	otcplen = skb->len - tcphoff;

	/* IP header checks: fragment, too short. */
	if (proto != IPPROTO_TCP || otcplen < sizeof(struct tcphdr)) {
		pr_warn("proto(%d) != IPPROTO_TCP, or too short. tcplen = %d\n",
			proto, otcplen);
		return NULL;
	}

	if (skb_copy_bits(skb, tcphoff, &tcph, sizeof(struct tcphdr))) {
		pr_warn("Could not copy TCP header.\n");
		return NULL;
	}

	nskb = alloc_skb(sizeof(struct ipv6hdr) + sizeof(struct tcphdr) +
				 LL_MAX_HEADER + len,
			 GFP_ATOMIC);
	if (nskb == NULL) {
		pr_warn("Could not allocate new skb\n");
		return NULL;
	}

	nskb->protocol = htons(ETH_P_IPV6);
	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	nip6h = (struct ipv6hdr *)skb_put(nskb, sizeof(struct ipv6hdr));
	memcpy(nip6h, ip6h, sizeof(struct ipv6hdr));
	nip6h->nexthdr = IPPROTO_TCP;

	skb_set_transport_header(nskb, sizeof(struct ipv6hdr));
	ntcphp = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memcpy(ntcphp, &tcph, sizeof(struct tcphdr));
	ntcphp->doff = sizeof(struct tcphdr) / 4;

	data = skb_put(nskb, len);
	memcpy(data, payload, len);

	tcplen = nskb->len - sizeof(struct ipv6hdr);

	/* Adjust TCP checksum */
	ntcphp->check = 0;
	ntcphp->check = csum_ipv6_magic(&nip6h->saddr, &nip6h->daddr, tcplen,
					IPPROTO_TCP,
					csum_partial(ntcphp, tcplen, 0));

	nip6h->payload_len = htons(tcplen);
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	/* __ip6_route_me_harder expects skb->dst to be set, and the caller may
	 * free skb before calling it, so reference the dst properly.
	 */
	skb_dst_set(nskb, dst_clone(skb_dst(skb)));

	return nskb;
}

static int tcp_ipv6_payload_length(const struct sk_buff *skb)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct tcphdr _tcph, *tcph;
	int tcphoff;
	__be16 frag_off;
	u8 proto;

	proto = iph->nexthdr;
	tcphoff = ipv6_skip_exthdr(skb, (u8 *)(iph + 1) - skb->data, &proto,
				   &frag_off);

	if (proto != IPPROTO_TCP) {
		pr_warn_ratelimited("TCP length called on non tcp packet.\n");
		return -1;
	}

	if (unlikely(tcphoff < 0 || tcphoff >= skb->len)) {
		pr_warn("Invalid TCP header offset.\n");
		return -1;
	}

	tcph = skb_header_pointer(skb, tcphoff, sizeof(_tcph), &_tcph);
	if (unlikely(tcph == NULL)) {
		pr_warn("Could not get TCP header.\n");
		return -1;
	}

	return skb->len - tcphoff - tcph->doff * 4;
}

static int ipv6_forward_finish(struct sk_buff *skb)
{
	struct net *net = dev_net(skb_dst(skb)->dev);
	struct dst_entry *dst = skb_dst(skb);

	__IP6_INC_STATS(net, ip6_dst_idev(dst), IPSTATS_MIB_OUTFORWDATAGRAMS);
	__IP6_ADD_STATS(net, ip6_dst_idev(dst), IPSTATS_MIB_OUTOCTETS,
			skb->len);

	return __dst_output(skb);
}

static int udp_ipv6_reply(struct sk_buff *oldskb, struct xt_action_param *par,
			  unsigned char *msg, size_t len)
{
	struct net *net = xt_net(par);
	struct sk_buff *nskb;
	struct udphdr oudph, *udph;
	unsigned char *data;
	int udphoff;
	unsigned int oudplen, hh_len;
	size_t udplen;
	const struct ipv6hdr *oip6h = ipv6_hdr(oldskb);
	struct ipv6hdr *ip6h;
	struct dst_entry *dst = NULL;
	u8 proto;
	__be16 frag_off;
	struct flowi6 fl6;
	const __u8 tclass = DEFAULT_TOS_VALUE;

	if ((!(ipv6_addr_type(&oip6h->saddr) & IPV6_ADDR_UNICAST)) ||
	    (!(ipv6_addr_type(&oip6h->daddr) & IPV6_ADDR_UNICAST))) {
		pr_warn("addr is not unicast.\n");
		return -1;
	}

	proto = oip6h->nexthdr;
	udphoff = ipv6_skip_exthdr(oldskb, ((u8 *)(oip6h + 1) - oldskb->data),
				   &proto, &frag_off);

	if (udphoff < 0 || udphoff > oldskb->len) {
		pr_warn("Cannot get UDP header.\n");
		return -1;
	}

	oudplen = oldskb->len - udphoff;

	/* IP header checks: fragment, too short. */
	if (proto != IPPROTO_UDP || oudplen < sizeof(struct udphdr)) {
		pr_warn("proto(%d) != IPPROTO_UDP, "
			"or too short. oudplen = %d\n",
			proto, oudplen);
		return -1;
	}

	if (skb_copy_bits(oldskb, udphoff, &oudph, sizeof(struct udphdr)))
		BUG();

	proto = oip6h->nexthdr;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_UDP;
	fl6.saddr = oip6h->daddr;
	fl6.daddr = oip6h->saddr;
	fl6.fl6_sport = oudph.dest;
	fl6.fl6_dport = oudph.source;
	security_skb_classify_flow(oldskb, flowi6_to_flowi_common(&fl6));
	dst = ip6_route_output(net, NULL, &fl6);
	if (dst == NULL || dst->error) {
		dst_release(dst);
		return -1;
	}
	dst = xfrm_lookup(net, dst, flowi6_to_flowi(&fl6), NULL, 0);
	if (IS_ERR(dst)) {
		return -1;
	}

	hh_len = (dst->dev->hard_header_len + 15) & ~15;
	nskb = alloc_skb(hh_len + 15 + dst->header_len +
				 sizeof(struct ipv6hdr) +
				 sizeof(struct udphdr) + dst->trailer_len + len,
			 GFP_ATOMIC);

	if (!nskb) {
		pr_warn("cannot alloc new skb\n");
		dst_release(dst);
		return -1;
	}

	skb_dst_set(nskb, dst);

	skb_reserve(nskb, LL_MAX_HEADER);

	skb_put(nskb, sizeof(struct ipv6hdr));
	skb_reset_network_header(nskb);
	ip6h = ipv6_hdr(nskb);
	ip6_flow_hdr(ip6h, tclass, 0);
	ip6h->hop_limit = ip6_dst_hoplimit(dst);

	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->saddr = oip6h->daddr;
	ip6h->daddr = oip6h->saddr;

	skb_reset_transport_header(nskb);
	udph = (struct udphdr *)skb_put(nskb, sizeof(struct udphdr));
	udph->source = oudph.dest;
	udph->dest = oudph.source;
	udph->len = htons(sizeof(struct udphdr) + len);

	data = skb_put(nskb, len);
	memcpy(data, msg, len);

	udplen = nskb->len - sizeof(struct ipv6hdr);
	udph->check = 0;

	udph->check = csum_ipv6_magic(&ipv6_hdr(nskb)->saddr,
				      &ipv6_hdr(nskb)->daddr, udplen,
				      IPPROTO_UDP,
				      csum_partial(udph, udplen, 0));

	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	/* route_me_harder6 expects skb->dst to be set, but will immediately
	 * overwrite it, so we can safely use noref here.
	 */
	skb_dst_set_noref(nskb, skb_dst(oldskb));
	if (route_me_harder6(xt_net(par), nskb))
		goto free_nskb;

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	ip6_local_out(xt_net(par), nskb->sk, nskb);
#else
	ip6_local_out(nskb);
#endif
	return 0;

free_nskb:
	kfree(nskb);
	return -1;
}

static struct sk_buff *udp_ipv6_payload(struct sk_buff *skb,
					unsigned char *payload, size_t len)
{
	struct udphdr udph, *nudphp;
	struct ipv6hdr *nip6h, *ip6h = ipv6_hdr(skb);
	struct sk_buff *nskb;
	unsigned char *data;
	unsigned int oudplen;
	size_t udplen;
	int udphoff;
	u8 proto;
	__be16 frag_off;

	if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST) ||
	    !(ipv6_addr_type(&ip6h->daddr) & IPV6_ADDR_UNICAST)) {
		pr_warn("addr is not unicast.\n");
		return NULL;
	}

	proto = ip6h->nexthdr;
	udphoff = ipv6_skip_exthdr(skb, (u8 *)(ip6h + 1) - skb->data, &proto,
				   &frag_off);

	if (udphoff < 0 || udphoff > skb->len) {
		pr_warn("Cannot get UDP header.\n");
		return NULL;
	}

	oudplen = skb->len - udphoff;

	/* IP header checks: fragment, too short. */
	if (proto != IPPROTO_UDP || oudplen < sizeof(struct udphdr)) {
		pr_warn("proto(%d) != IPPROTO_UDP, or too short. udplen = %d\n",
			proto, oudplen);
		return NULL;
	}

	if (skb_copy_bits(skb, udphoff, &udph, sizeof(struct udphdr))) {
		pr_warn("Could not copy UDP header.\n");
		return NULL;
	}

	nskb = alloc_skb(sizeof(struct ipv6hdr) + sizeof(struct udphdr) +
				 LL_MAX_HEADER + len,
			 GFP_ATOMIC);
	if (nskb == NULL) {
		pr_warn("Could not allocate new skb\n");
		return NULL;
	}

	nskb->protocol = htons(ETH_P_IPV6);
	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	nip6h = (struct ipv6hdr *)skb_put(nskb, sizeof(struct ipv6hdr));
	memcpy(nip6h, ip6h, sizeof(struct ipv6hdr));
	nip6h->nexthdr = IPPROTO_UDP;

	skb_set_transport_header(nskb, sizeof(struct ipv6hdr));
	nudphp = (struct udphdr *)skb_put(nskb, sizeof(struct udphdr));
	memcpy(nudphp, &udph, sizeof(struct udphdr));

	data = skb_put(nskb, len);
	memcpy(data, payload, len);

	udplen = nskb->len - sizeof(struct ipv6hdr);

	/* Adjust UDP checksum */
	nudphp->check = 0;
	nudphp->check = csum_ipv6_magic(&nip6h->saddr, &nip6h->daddr, udplen,
					IPPROTO_UDP,
					csum_partial(nudphp, udplen, 0));

	nip6h->payload_len = htons(udplen);
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	/* __ip6_route_me_harder expects skb->dst to be set, and the caller may
	 * free skb before calling it, so reference the dst properly.
	 */
	skb_dst_set(nskb, dst_clone(skb_dst(skb)));

	return nskb;
}

#endif /* USE_IPV6 */

static int udp_ipv4_reply(struct sk_buff *oldskb, struct xt_action_param *par,
			  unsigned char *msg, size_t len)
{
	struct sk_buff *nskb;
	const struct iphdr *oiph;
	struct iphdr *niph;
	const struct udphdr *oth;
	struct udphdr _oudph, *udph;
	unsigned char *data;

	/* IP header checks: fragment. */
	if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET)) {
		pr_warn("Packet is fragmented\n");
		return -1;
	}

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb), sizeof(_oudph),
				 &_oudph);
	if (oth == NULL) {
		pr_warn("Cannot get header pointer\n");
		return -1;
	}

	if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST)) {
		pr_warn("Not a unicast packet\n");
		return -1;
	}

	oiph = ip_hdr(oldskb);

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct udphdr) +
				 LL_MAX_HEADER + len,
			 GFP_ATOMIC);
	if (!nskb)
		return -1;

	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	niph->version = 4;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->id = 0;
	niph->frag_off = htons(IP_DF);
	niph->protocol = IPPROTO_UDP;
	niph->check = 0;
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;

	skb_reset_transport_header(nskb);
	udph = (struct udphdr *)skb_put(nskb, sizeof(struct udphdr));
	memset(udph, 0, sizeof(*udph));
	udph->source = oth->dest;
	udph->dest = oth->source;
	udph->len = htons(sizeof(struct udphdr) + len);

	data = skb_put(nskb, len);
	memcpy(data, msg, len);

	/* route_me_harder4 expects skb->dst to be set, but will immediately
	 * overwrite it, so we can safely use noref here.
	 */
	skb_dst_set_noref(nskb, skb_dst(oldskb));

	nskb->protocol = htons(ETH_P_IP);
	if (route_me_harder4(xt_net(par), nskb))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	if (ip_local_out(xt_net(par), nskb->sk, nskb))
		goto free_nskb;
#else
	if (ip_local_out(nskb))
		goto free_nskb;
#endif

	return 0;

free_nskb:
	kfree_skb(nskb);
	return -1;
}

static int tcp_ipv4_reply(struct sk_buff *oldskb, struct xt_action_param *par,
			  unsigned char *msg, size_t len)
{
	struct sk_buff *nskb;
	const struct iphdr *oiph;
	struct iphdr *niph;
	const struct tcphdr *oth;
	int hook;
	struct tcphdr _otcph, *tcph;
	unsigned char *data;
	size_t tcplen;

	/* IP header checks: fragment. */
	if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET)) {
		pr_warn("Packet is fragmented\n");
		return -1;
	}

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb), sizeof(_otcph),
				 &_otcph);
	if (oth == NULL) {
		pr_warn("Cannot get header pointer\n");
		return -1;
	}

	/* No reply for RST. */
	if (oth->rst) {
		pr_warn("RST is set\n");
		return -1;
	}

	if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST)) {
		pr_warn("Not a unicast packet\n");
		return -1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	hook = xt_hooknum(par);
#else
	hook = par->hooknum;
#endif

	/* Check checksum */
	if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP)) {
		pr_warn("TCP checksum is invalid\n");
		return -1;
	}
	oiph = ip_hdr(oldskb);

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
				 LL_MAX_HEADER + len,
			 GFP_ATOMIC);
	if (!nskb)
		return -1;

	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	niph->version = 4;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->id = 0;
	niph->frag_off = htons(IP_DF);
	niph->protocol = IPPROTO_TCP;
	niph->check = 0;
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;

	skb_reset_transport_header(nskb);
	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memset(tcph, 0, sizeof(*tcph));
	tcph->source = oth->dest;
	tcph->dest = oth->source;
	tcph->doff = sizeof(struct tcphdr) / 4;

	tcph->seq = htonl(ntohl(oth->ack_seq));
	tcph->ack_seq =
		htonl(ntohl(oth->seq) + oth->syn + oth->fin + oldskb->len -
		      ip_hdrlen(oldskb) - (oth->doff << 2));
	tcph->psh = 1;
	tcph->ack = 1;

	data = skb_put(nskb, len);
	memcpy(data, msg, len);

	tcplen = (nskb->len - (niph->ihl << 2));
	tcph->check = 0;
	tcph->check = csum_tcpudp_magic(niph->saddr, niph->daddr, tcplen,
					IPPROTO_TCP,
					csum_partial(tcph, tcplen, 0));
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	/* route_me_harder4 expects skb->dst to be set, but will immediately
	 * overwrite it, so we can safely use noref here.
	 */
	skb_dst_set_noref(nskb, skb_dst(oldskb));

	nskb->protocol = htons(ETH_P_IP);
	if (route_me_harder4(xt_net(par), nskb))
		goto free_nskb;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
	niph->ttl = ip4_dst_hoplimit(skb_dst(nskb));
#else
	niph->ttl = dst_metric(skb_dst(nskb), RTAX_HOPLIMIT);
#endif

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	if (ip_local_out(xt_net(par), nskb->sk, nskb))
		goto free_nskb;
#else
	if (ip_local_out(nskb))
		goto free_nskb;
#endif

	return 0;

free_nskb:
	kfree_skb(nskb);
	return -1;
}

int tcp_reply(struct sk_buff *oldskb, struct xt_action_param *par,
	      unsigned char *msg, size_t len)
{
#ifdef USE_IPV6
	if (oldskb->protocol == htons(ETH_P_IPV6))
		return tcp_ipv6_reply(oldskb, par, msg, len);
#endif
	return tcp_ipv4_reply(oldskb, par, msg, len);
}

int udp_reply(struct sk_buff *oldskb, struct xt_action_param *par,
	      unsigned char *msg, size_t len)
{
#ifdef USE_IPV6
	if (oldskb->protocol == htons(ETH_P_IPV6))
		return udp_ipv6_reply(oldskb, par, msg, len);
#endif
	return udp_ipv4_reply(oldskb, par, msg, len);
}

static struct sk_buff *tcp_ipv4_payload(struct sk_buff *skb,
					unsigned char *payload, size_t len)
{
	struct tcphdr tcph, *ntcphp;
	struct iphdr *niph;
	struct sk_buff *nskb;
	unsigned char *data;
	size_t tcplen;
	int tcphoff;

	/* IP header checks: fragment. */
	if (ip_hdr(skb)->frag_off & htons(IP_OFFSET))
		return NULL;

	tcphoff = skb_transport_offset(skb);
	if (tcphoff < 0 || tcphoff >= skb->len) {
		pr_warn("Cannot get TCP header.\n");
		return NULL;
	}

	if (skb_copy_bits(skb, tcphoff, &tcph, sizeof(struct tcphdr))) {
		pr_warn("Could not copy TCP header.\n");
		return NULL;
	}

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
				 LL_MAX_HEADER + len,
			 GFP_ATOMIC);
	if (nskb == NULL) {
		pr_warn("Could not allocate new skb\n");
		return NULL;
	}

	nskb->protocol = htons(ETH_P_IP);
	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	memcpy(niph, ip_hdr(skb), sizeof(struct iphdr));
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->frag_off = htons(IP_DF);

	skb_set_transport_header(nskb, sizeof(struct iphdr));
	ntcphp = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memcpy(ntcphp, &tcph, sizeof(struct tcphdr));
	ntcphp->doff = sizeof(struct tcphdr) / 4;

	data = skb_put(nskb, len);
	memcpy(data, payload, len);

	tcplen = nskb->len - ip_hdrlen(nskb);
	ntcphp->check = 0;
	ntcphp->check = csum_tcpudp_magic(niph->saddr, niph->daddr, tcplen,
					  IPPROTO_TCP,
					  csum_partial(ntcphp, tcplen, 0));

	niph->tot_len = htons(nskb->len);
	ip_send_check(niph);

	/* ip_route_me_harder expects skb->dst to be set, and the caller may
	 * free skb before calling it, so reference the dst properly.
	 */
	skb_dst_set(nskb, dst_clone(skb_dst(skb)));

	return nskb;
}

static struct sk_buff *udp_ipv4_payload(struct sk_buff *skb,
					unsigned char *payload, size_t len)
{
	struct udphdr udph, *nudphp;
	struct iphdr *niph;
	struct sk_buff *nskb;
	unsigned char *data;
	size_t udplen;
	int udphoff;

	/* IP header checks: fragment. */
	if (ip_hdr(skb)->frag_off & htons(IP_OFFSET))
		return NULL;

	udphoff = skb_transport_offset(skb);
	if (udphoff < 0 || udphoff >= skb->len) {
		pr_warn("Cannot get UDP header.\n");
		return NULL;
	}

	if (skb_copy_bits(skb, udphoff, &udph, sizeof(struct udphdr))) {
		pr_warn("Could not copy UDP header.\n");
		return NULL;
	}

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct udphdr) +
				 LL_MAX_HEADER + len,
			 GFP_ATOMIC);
	if (nskb == NULL) {
		pr_warn("Could not allocate new skb\n");
		return NULL;
	}

	nskb->protocol = htons(ETH_P_IP);
	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	memcpy(niph, ip_hdr(skb), sizeof(struct iphdr));
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->frag_off = htons(IP_DF);

	skb_set_transport_header(nskb, sizeof(struct iphdr));
	nudphp = (struct udphdr *)skb_put(nskb, sizeof(struct udphdr));
	memcpy(nudphp, &udph, sizeof(struct udphdr));

	data = skb_put(nskb, len);
	memcpy(data, payload, len);

	udplen = nskb->len - ip_hdrlen(nskb);
	nudphp->check = 0;
	nudphp->len = htons(udplen);
	nudphp->check = csum_tcpudp_magic(niph->saddr, niph->daddr, udplen,
					  IPPROTO_UDP,
					  csum_partial(nudphp, udplen, 0));

	niph->tot_len = htons(nskb->len);
	ip_send_check(niph);

	/* ip_route_me_harder expects skb->dst to be set, and the caller may
	 * free skb before calling it, so reference the dst properly.
	 */
	skb_dst_set(nskb, dst_clone(skb_dst(skb)));

	return nskb;
}

static int tcp_ipv4_payload_length(const struct sk_buff *skb)
{
	struct tcphdr _tcph, *tcph;
	int tcphoff;

	if (ip_hdr(skb)->protocol != IPPROTO_TCP) {
		pr_warn_ratelimited("TCP length called on non tcp packet.\n");
		return -1;
	}

	tcphoff = ip_hdrlen(skb);
	if (unlikely(tcphoff < 0 || tcphoff >= skb->len)) {
		pr_warn("Invalid TCP header offset.\n");
		return -1;
	}

	tcph = skb_header_pointer(skb, tcphoff, sizeof(_tcph), &_tcph);
	if (unlikely(tcph == NULL)) {
		pr_warn("Could not get TCP header.\n");
		return -1;
	}

	return skb->len - tcphoff - tcph->doff * 4;
}

struct sk_buff *tcp_payload(struct sk_buff *skb, unsigned char *payload,
			    size_t len)
{
#ifdef USE_IPV6
	if (skb->protocol == htons(ETH_P_IPV6))
		return tcp_ipv6_payload(skb, payload, len);
#endif
	return tcp_ipv4_payload(skb, payload, len);
}

struct sk_buff *udp_payload(struct sk_buff *skb, unsigned char *payload,
			    size_t len)
{
#ifdef USE_IPV6
	if (skb->protocol == htons(ETH_P_IPV6))
		return udp_ipv6_payload(skb, payload, len);
#endif
	return udp_ipv4_payload(skb, payload, len);
}

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)) && \
     (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)))
static bool ipv4_gso_exceeds_dst_mtu(const struct sk_buff *skb)
{
	unsigned int mtu;

	if (skb->local_df || !skb_is_gso(skb))
		return false;

	mtu = dst_mtu(skb_dst(skb));

	/* if seglen > mtu, do software segmentation for IP fragmentation on
	 * output.  DF bit cannot be set since ip_forward would have sent
	 * icmp error.
	 */
	return skb_gso_network_seglen(skb) > mtu;
}

/* called if GSO skb needs to be fragmented on forward */
static int ipv4_forward_finish_gso(struct sk_buff *skb)
{
	netdev_features_t features;
	struct sk_buff *segs;
	int ret = 0;

	features = netif_skb_dev_features(skb, skb_dst(skb)->dev);
	segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
	if (IS_ERR(segs)) {
		kfree_skb(skb);
		return -ENOMEM;
	}

	consume_skb(skb);

	do {
		struct sk_buff *nskb = segs->next;
		int err;

		segs->next = NULL;
		err = __dst_output(segs);

		if (err && ret == 0)
			ret = err;
		segs = nskb;
	} while (segs);

	return ret;
}
#endif

static void __ip_rt_get_source(u8 *addr, struct sk_buff *skb, struct rtable *rt)
{
	__be32 src;

	// Too much functionality for the input case is not exported.
	BUG_ON(rt_is_input_route(rt));

	src = ip_hdr(skb)->saddr;
	memcpy(addr, &src, 4);
}

static void __ip_forward_options(struct sk_buff *skb)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	unsigned char *optptr;
	struct rtable *rt = skb_rtable(skb);
	unsigned char *raw = skb_network_header(skb);

	if (opt->rr_needaddr) {
		optptr = (unsigned char *)raw + opt->rr;
		__ip_rt_get_source(&optptr[optptr[2] - 5], skb, rt);
		opt->is_changed = 1;
	}
	if (opt->srr_is_hit) {
		int srrptr, srrspace;

		optptr = raw + opt->srr;

		for (srrptr = optptr[2], srrspace = optptr[1];
		     srrptr <= srrspace; srrptr += 4) {
			if (srrptr + 3 > srrspace)
				break;
			if (memcmp(&opt->nexthop, &optptr[srrptr - 1], 4) == 0)
				break;
		}
		if (srrptr + 3 <= srrspace) {
			opt->is_changed = 1;
			ip_hdr(skb)->daddr = opt->nexthop;
			__ip_rt_get_source(&optptr[srrptr - 1], skb, rt);
			optptr[2] = srrptr + 4;
		} else {
			net_crit_ratelimited("%s(): Argh! Destination lost!\n",
					     __func__);
		}
		if (opt->ts_needaddr) {
			optptr = raw + opt->ts;
			__ip_rt_get_source(&optptr[optptr[2] - 9], skb, rt);
			opt->is_changed = 1;
		}
	}
	if (opt->is_changed) {
		opt->is_changed = 0;
		ip_send_check(ip_hdr(skb));
	}
}

static int ipv4_forward_finish(struct sk_buff *skb)
{
	struct net *net = dev_net(skb_dst(skb)->dev);
	struct ip_options *opt = &IPCB(skb)->opt;

	__IP_INC_STATS(net, IPSTATS_MIB_OUTFORWDATAGRAMS);
	__IP_ADD_STATS(net, IPSTATS_MIB_OUTOCTETS, skb->len);

	if (unlikely(opt->optlen))
		__ip_forward_options(skb);

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)) && \
     (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)))
	if (ipv4_gso_exceeds_dst_mtu(skb))
		return ipv4_forward_finish_gso(skb);
#endif

	return __dst_output(skb);
}

int finish_send(struct sk_buff *skb)
{
#ifdef USE_IPV6
	if (skb->protocol == htons(ETH_P_IPV6))
		return ipv6_forward_finish(skb);
#endif
	return ipv4_forward_finish(skb);
}

int tcp_payload_length(const struct sk_buff *skb)
{
#ifdef USE_IPV6
	if (skb->protocol == htons(ETH_P_IPV6))
		return tcp_ipv6_payload_length(skb);
#endif
	return tcp_ipv4_payload_length(skb);
}

static int route_me_harder4(struct net *net, struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	return ip_route_me_harder(net, skb->sk, skb, RTN_UNSPEC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	/*
	 * OpenWrt has backported a change from 5.10 (kernel commit 46d6c5ae953)
	 * to 4.14, changing the type of ip_route_me_harder. We can't identify
	 * that in the preprocessor alone so use GCC builtins to evaluate the
	 * type and call the function in the right way.
	 */

	typedef int (*type_after_510)(struct net *, struct sock *,
				      struct sk_buff *, unsigned int);
	typedef int (*type_after_440)(struct net *, struct sk_buff *,
				      unsigned int);

	/*
	 * Use an intermediate variable to silence GCC warning about the types
	 * being incompatible.
	 */
	void *func = ip_route_me_harder;

	if (__builtin_types_compatible_p(typeof(&ip_route_me_harder),
					 type_after_510)) {
		return ((type_after_510)func)(net, skb->sk, skb, RTN_UNSPEC);
	} else if (__builtin_types_compatible_p(typeof(&ip_route_me_harder),
						type_after_440)) {
		return ((type_after_440)func)(net, skb, RTN_UNSPEC);
	} else {
		/*
		 * Hopefully this is loud enough for anyone to notice.
		 */
		WARN_ONCE(1, "ip_route_me_harder has unsupported type");
		return -EFAULT;
	}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	return ip_route_me_harder(net, skb, RTN_UNSPEC);
#else
	(void)net;
	return ip_route_me_harder(skb, RTN_UNSPEC);
#endif
}

#ifdef USE_IPV6
static int route_me_harder6(struct net *net, struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	return ip_route_me_harder(net, skb->sk, skb, RTN_UNSPEC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)

	/* See route_me_harder4. */
	typedef int (*type_after_510)(struct net *, struct sock *,
				      struct sk_buff *);
	typedef int (*type_after_440)(struct net *, struct sk_buff *);
	void *func = ip6_route_me_harder;
	if (__builtin_types_compatible_p(typeof(&ip6_route_me_harder),
					 type_after_510)) {
		return ((type_after_510)func)(net, skb->sk, skb);
	} else if (__builtin_types_compatible_p(typeof(&ip6_route_me_harder),
						type_after_440)) {
		return ((type_after_440)func)(net, skb);
	} else {
		WARN_ONCE(1, "ip6_route_me_harder has unsupported type");
		return -EFAULT;
	}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	return ip6_route_me_harder(net, skb);
#else
	(void)net;
	return ip6_route_me_harder(skb);
#endif
}
#endif

int route_me_harder(struct net *net, struct sk_buff *skb)
{
#ifdef USE_IPV6
	if (skb->protocol == htons(ETH_P_IPV6))
		return route_me_harder6(net, skb);
#endif
	return route_me_harder4(net, skb);
}
