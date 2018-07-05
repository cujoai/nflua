/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2003 USAGI/WIDE Project, Yasuyuki Kozakai <yasuyuki.kozakai@toshiba.co.jp>
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2005-2007 Patrick McHardy <kaber@trash.net>
 * (C) 2017-2018 CUJO LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_route.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

static int tcp_ipv6_reply(struct sk_buff *oldskb,
			  struct xt_action_param *par,
			  unsigned char *msg, size_t len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	struct net *net = dev_net((par->state->in != NULL) ? par->state->in : par->state->out);
#else
	struct net *net = dev_net((par->in != NULL) ? par->in : par->out);
#endif
	struct sk_buff *nskb;
	struct tcphdr otcph, *tcph;
	unsigned int otcplen, hh_len;
	unsigned char *data;
	size_t tcplen;
	int tcphoff;
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
	tcphoff = ipv6_skip_exthdr(oldskb, ((u8*)(oip6h+1) - oldskb->data),
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

	/* Check checksum. */
	if (csum_ipv6_magic(&oip6h->saddr, &oip6h->daddr, otcplen, IPPROTO_TCP,
			    skb_checksum(oldskb, tcphoff, otcplen, 0))) {
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
		net_dbg_ratelimited("cannot alloc skb\n");
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	ip6_local_out(par->state->net, nskb->sk, nskb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	ip6_local_out(par->net, nskb->sk, nskb);
#else
 	ip6_local_out(nskb);
#endif	

	return 0;
}
#endif

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
	hook = par->state->hook;
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	if (ip_route_me_harder(par->state->net, nskb, RTN_UNSPEC))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	if (ip_route_me_harder(par->net, nskb, RTN_UNSPEC))
#else
	if (ip_route_me_harder(nskb, RTN_UNSPEC))
#endif
		goto free_nskb;

	niph->ttl	= ip4_dst_hoplimit(skb_dst(nskb));

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	ip_local_out(par->state->net, nskb->sk, nskb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	ip_local_out(par->net, nskb->sk, nskb);
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
