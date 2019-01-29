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
