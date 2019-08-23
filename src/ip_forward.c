/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP forwarding functionality.
 *
 * Authors:	see ip.c
 *
 * Fixes:
 *		Many		:	Split from ip.c , see ip_input.c for
 *					history.
 *		Dave Gregorich	:	NULL ip_rt_put fix for multicast
 *					routing.
 *		Jos Vos		:	Add call_out_firewall before sending,
 *					use output device for accounting.
 *		Jos Vos		:	Call forward firewall after routing
 *					(always use output device).
 *		Mike McLagan	:	Routing by source
 */

static bool ip_gso_exceeds_dst_mtu(const struct sk_buff *skb)
{
	unsigned int mtu;

	if (skb->local_df || !skb_is_gso(skb))
		return false;

	mtu = ip_dst_mtu_maybe_forward(skb_dst(skb), true);

	/* if seglen > mtu, do software segmentation for IP fragmentation on
	 * output.  DF bit cannot be set since ip_forward would have sent
	 * icmp error.
	 */
	return skb_gso_network_seglen(skb) > mtu;
}

/* called if GSO skb needs to be fragmented on forward */
static int ip_forward_finish_gso(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	netdev_features_t features;
	struct sk_buff *segs;
	int ret = 0;

	features = netif_skb_dev_features(skb, dst->dev);
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
		err = dst_output(segs);

		if (err && ret == 0)
			ret = err;
		segs = nskb;
	} while (segs);

	return ret;
}

