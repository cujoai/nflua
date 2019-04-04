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
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#ifdef MODULE
#include <linux/kallsyms.h>

static void (*__ip_forward_options)(struct sk_buff *);

bool nf_util_init(void)
{
	return (__ip_forward_options = (void(*)(struct sk_buff*))
		kallsyms_lookup_name("ip_forward_options")) != NULL;
}

#else

#define __ip_forward_options(skb) (ip_forward_options(skb))

bool nf_util_init(void)
{
	return true;
}
#endif

#include "nf_util.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
#define __dst_output(skb) (dst_output(dev_net(skb_dst(skb)->dev), skb->sk, skb))
#define __ip_route_me_harder(skb) \
	(ip_route_me_harder(dev_net(skb_dst(skb)->dev), skb, RTN_UNSPEC))

#if IS_ENABLED(CONFIG_IPV6)
#define __ip6_route_me_harder(skb) \
	(ip6_route_me_harder(dev_net(skb_dst(skb)->dev), skb))
#endif /* CONFIG_IPV6 */
#else
#define __dst_output(skb) (dst_output(skb))
#define __ip_route_me_harder(skb) (ip_route_me_harder(skb, RTN_UNSPEC))

#if IS_ENABLED(CONFIG_IPV6)
#define __ip6_route_me_harder(skb) (ip6_route_me_harder(skb))
#endif /* CONFIG_IPV6 */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
#define __IP_INC_STATS IP_INC_STATS_BH
#define __IP_ADD_STATS IP_ADD_STATS_BH
#if IS_ENABLED(CONFIG_IPV6)
#define __IP6_INC_STATS IP6_INC_STATS_BH
#define __IP6_ADD_STATS IP6_ADD_STATS_BH
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#define net_dbg_ratelimited(fmt, ...)			\
	do {						\
		if (net_ratelimit())			\
			pr_debug(fmt, ##__VA_ARGS__);	\
	} while (0)
#endif

#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_route.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
static inline void ip6_flow_hdr(struct ipv6hdr *hdr, unsigned int tclass,
				__be32 flowlabel)
{
	*(__be32 *)hdr = ntohl(0x60000000 | (tclass << 20)) | flowlabel;
}
#endif

static int tcp_ipv6_reply(struct sk_buff *oldskb,
			  struct xt_action_param *par,
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
#define DEFAULT_TOS_VALUE	0x0U
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
	tcphoff = ipv6_skip_exthdr(oldskb, ((u8*)(oip6h + 1) - oldskb->data),
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
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
	security_skb_classify_flow(oldskb, flowi6_to_flowi(&fl6));
	dst = ip6_route_output(net, NULL, &fl6);
	if (dst == NULL || dst->error) {
		dst_release(dst);
		return -1;
	}
	dst = xfrm_lookup(net, dst, flowi6_to_flowi(&fl6), NULL, 0);
	if (IS_ERR(dst)) {
		return -1;
	}

	hh_len = (dst->dev->hard_header_len + 15)&~15;
	nskb = alloc_skb(hh_len + 15 + dst->header_len + sizeof(struct ipv6hdr)
			 + sizeof(struct tcphdr) + dst->trailer_len + len,
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
	tcph->doff = sizeof(struct tcphdr)/4;
	tcph->source = otcph.dest;
	tcph->dest = otcph.source;

	tcph->seq = otcph.ack_seq;
	tcph->ack_seq = htonl(ntohl(otcph.seq) + otcph.syn + otcph.fin
			      + otcplen - (otcph.doff<<2));

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
				      &ipv6_hdr(nskb)->daddr,
				      tcplen, IPPROTO_TCP,
				      csum_partial(tcph, tcplen, 0));
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	nf_ct_attach(nskb, oldskb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
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
	tcphoff = ipv6_skip_exthdr(skb, (u8*)(ip6h + 1) - skb->data,
				   &proto, &frag_off);

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
	                 LL_MAX_HEADER + len, GFP_ATOMIC);
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

	skb_reset_transport_header(nskb);
	ntcphp = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memcpy(ntcphp, &tcph, sizeof(struct tcphdr));
	ntcphp->doff = sizeof(struct tcphdr) / 4;

	data = skb_put(nskb, len);
	memcpy(data, payload, len);

	tcplen = nskb->len - sizeof(struct ipv6hdr);

	/* Adjust TCP checksum */
	ntcphp->check = 0;
	ntcphp->check = csum_ipv6_magic(&nip6h->saddr, &nip6h->daddr,
				      tcplen, IPPROTO_TCP,
				      csum_partial(ntcphp, tcplen, 0));

	nip6h->payload_len = htons(tcplen);
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	/* ip6_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(skb));

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
	tcphoff = ipv6_skip_exthdr(skb, (u8*)(iph + 1) - skb->data,
				   &proto, &frag_off);

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
	__IP6_ADD_STATS(net, ip6_dst_idev(dst), IPSTATS_MIB_OUTOCTETS, skb->len);

	return __dst_output(skb);
}
#endif /* IS_ENABLED(CONFIG_IPV6) */

static int tcp_ipv4_reply(struct sk_buff *oldskb,
		          struct xt_action_param *par,
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

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
				 sizeof(_otcph), &_otcph);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
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
			 LL_MAX_HEADER + len, GFP_ATOMIC);
	if (!nskb)
		return -1;

	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	niph->version	= 4;
	niph->ihl	= sizeof(struct iphdr) / 4;
	niph->tos	= 0;
	niph->id	= 0;
	niph->frag_off	= htons(IP_DF);
	niph->protocol	= IPPROTO_TCP;
	niph->check	= 0;
	niph->saddr	= oiph->daddr;
	niph->daddr	= oiph->saddr;

	skb_reset_transport_header(nskb);
	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memset(tcph, 0, sizeof(*tcph));
	tcph->source	= oth->dest;
	tcph->dest	= oth->source;
	tcph->doff	= sizeof(struct tcphdr) / 4;

	tcph->seq = htonl(ntohl(oth->ack_seq));
	tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
		oldskb->len - ip_hdrlen(oldskb) -
		(oth->doff << 2));
	tcph->psh = 1;
	tcph->ack = 1;

	data = skb_put(nskb, len);
	memcpy(data, msg, len);

	tcplen = (nskb->len - (niph->ihl << 2));
	tcph->check = 0;
	tcph->check = csum_tcpudp_magic(niph->saddr, niph->daddr,
					tcplen, IPPROTO_TCP,
					csum_partial(tcph, tcplen, 0));
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(oldskb));

	nskb->protocol = htons(ETH_P_IP);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	if (ip_route_me_harder(xt_net(par), nskb, RTN_UNSPEC))
#else
	if (ip_route_me_harder(nskb, RTN_UNSPEC))
#endif
		goto free_nskb;

	niph->ttl	= ip4_dst_hoplimit(skb_dst(nskb));

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	ip_local_out(xt_net(par), nskb->sk, nskb);
#else
 	ip_local_out(nskb);
#endif

	return 0;

 free_nskb:
	kfree_skb(nskb);
	return -1;
}

int tcp_reply(struct sk_buff *oldskb, struct xt_action_param *par,
	      unsigned char *msg, size_t len)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (oldskb->protocol == htons(ETH_P_IPV6))
		return tcp_ipv6_reply(oldskb, par, msg, len);
#endif
	return tcp_ipv4_reply(oldskb, par, msg, len);
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
	                  LL_MAX_HEADER + len, GFP_ATOMIC);
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

	skb_reset_transport_header(nskb);
	ntcphp = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memcpy(ntcphp, &tcph, sizeof(struct tcphdr));
	ntcphp->doff = sizeof(struct tcphdr) / 4;

	data = skb_put(nskb, len);
	memcpy(data, payload, len);

	tcplen = nskb->len - ip_hdrlen(nskb);
	ntcphp->check = 0;
	ntcphp->check = csum_tcpudp_magic(niph->saddr, niph->daddr,
	                                 tcplen, IPPROTO_TCP,
	                                 csum_partial(ntcphp, tcplen, 0));

	niph->tot_len = htons(nskb->len);
	ip_send_check(niph);

	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(skb));

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

struct sk_buff *tcp_payload(struct sk_buff *skb,
                            unsigned char *payload, size_t len)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (skb->protocol == htons(ETH_P_IPV6))
		return tcp_ipv6_payload(skb, payload, len);
#endif
	return tcp_ipv4_payload(skb, payload, len);
}

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) && \
	 (LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)))
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

static int ipv4_forward_finish(struct sk_buff *skb)
{
	struct net *net = dev_net(skb_dst(skb)->dev);
	struct ip_options *opt = &IPCB(skb)->opt;

	__IP_INC_STATS(net, IPSTATS_MIB_OUTFORWDATAGRAMS);
	__IP_ADD_STATS(net, IPSTATS_MIB_OUTOCTETS, skb->len);

	if (unlikely(opt->optlen))
		__ip_forward_options(skb);

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) && \
	 (LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)))
	if (ipv4_gso_exceeds_dst_mtu(skb))
		return ipv4_forward_finish_gso(skb);
#endif

	return __dst_output(skb);
}

int tcp_send(struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (skb->protocol == htons(ETH_P_IPV6))
		return ipv6_forward_finish(skb);
#endif
	return ipv4_forward_finish(skb);
}

int tcp_payload_length(const struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (skb->protocol == htons(ETH_P_IPV6))
		return tcp_ipv6_payload_length(skb);
#endif
	return tcp_ipv4_payload_length(skb);
}

int route_me_harder(struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (skb->protocol == htons(ETH_P_IPV6))
		return __ip6_route_me_harder(skb);
#endif /* CONFIG_IPV6 */
	return __ip_route_me_harder(skb);
}
