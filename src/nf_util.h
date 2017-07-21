#ifndef _NF_UTIL_H
#define _NF_UTIL_H

#include <linux/types.h>
#include <linux/skbuff.h>

int tcp_reply(const struct sk_buff *, int, unsigned char *, size_t);

#endif
