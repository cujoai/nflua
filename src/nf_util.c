/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2017      CUJO LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/slab.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

int tcp_reply(const struct sk_buff *oldskb, int hook, unsigned char *msg,
	size_t len)
{
	struct sk_buff *nskb;
	const struct iphdr *oiph;
	struct iphdr *niph;
	const struct tcphdr *oth;
	struct tcphdr _otcph, *tcph;
	unsigned char *data;
	size_t tcplen;

	/* IP header checks: fragment. */
	if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
		return -1;

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
				 sizeof(_otcph), &_otcph);
	if (oth == NULL)
		return -1;

	/* No reply for RST. */
	if (oth->rst)
		return -1;

	if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		return -1;

	/* Check checksum */
	if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
		return -1;
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
	if (ip_route_me_harder(nskb, RTN_UNSPEC))
		goto free_nskb;

	niph->ttl	= ip4_dst_hoplimit(skb_dst(nskb));

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

	ip_local_out(nskb);
	return 0;

 free_nskb:
	kfree_skb(nskb);
	return -1;
}

