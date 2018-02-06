#ifndef _NF_UTIL_H
#define _NF_UTIL_H

#include <linux/types.h>
#include <linux/skbuff.h>

int tcp_reply(struct sk_buff *, struct xt_action_param *,
		unsigned char *, size_t);

#endif
