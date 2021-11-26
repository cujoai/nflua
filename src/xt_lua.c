/*
 * Copyright (C) 2017-2019  CUJO LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/atomic.h>
#include <linux/ratelimit.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/version.h>

#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/netlink.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/netns/generic.h>
#include <net/genetlink.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/kfifo.h>
#include <linux/jiffies.h>
#include <linux/timer.h>

#include <net/netfilter/nf_conntrack_acct.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <luadata.h>

#include "xt_lua.h"

#include "nf_util.h"
#include "luaconntrack.h"
#include "luautil.h"

#ifndef NFLUA_SETPAUSE
#define NFLUA_SETPAUSE 100
#endif /* NFLUA_SETPAUSE */

#ifndef NETLINK_NFLUA
#define NETLINK_NFLUA NETLINK_GENERIC
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
static inline u32 skb_mac_header_len(const struct sk_buff *skb)
{
	return skb->network_header - skb->mac_header;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define kpi_nf_conn_acct_find(ct) \
	(nf_conn_acct_find(ct) == NULL ? NULL : nf_conn_acct_find(ct)->counter)
#else
#define kpi_nf_conn_acct_find(ct) nf_conn_acct_find(ct)
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CUJO LLC <opensource@cujo.com>");

MODULE_DESCRIPTION("Netfilter Lua module");

static int netlink_family = NETLINK_NFLUA;
module_param(netlink_family, int, 0660);

#define NFLUA_SOCK "nflua_sock"

static int xt_lua_net_id __read_mostly;
static size_t total_alloc_mem = 0;
static unsigned int total_elapsed_time_usec = 0;
struct xt_lua_net {
	/* ABI relied on by luaconntrack: This must be the first element. */
	struct net *net;

	size_t alloc;
	lua_State *L;
	spinlock_t lock;
};

static inline struct xt_lua_net *xt_lua_pernet(struct net *net)
{
	return net_generic(net, xt_lua_net_id);
}

#define NFLUA_SKBCLONE "nflua_skbclone"
#define NFLUA_CTXENTRY "nflua_ctx"
struct nflua_ctx {
	struct sk_buff *skb;
	struct xt_action_param *par;
	int frame;
	int packet;
};

struct nftimer_ctx {
	struct timer_list timer;
	struct xt_lua_net *xt_lua;
};

static struct genl_family genl_nflua_family;

static struct net *gennet;

static struct nla_policy genl_nflua_policy[GENL_NFLUA_ATTR_MAX + 1] = {
	[GENL_NFLUA_ATTR_MSG] = { .type = NLA_BINARY,
				  .len = GENL_NFLUA_ATTR_MSG_MAX },
};

static atomic_t match_mask = ATOMIC_INIT(0);

static void nflua_destroy(const struct xt_mtdtor_param *par)
{
}

static int nflua_checkentry(const struct xt_mtchk_param *par)
{
	return 0;
}

static void nflua_tg_destroy(const struct xt_tgdtor_param *par)
{
}

static int nflua_tg_checkentry(const struct xt_tgchk_param *par)
{
	return 0;
}

/* LUA errors in lunatik are outputted via this function */
static int nflua_msghandler(lua_State *L)
{
	const char *msg = lua_tostring(L, 1);

	if (msg == NULL) {
		if (luaL_callmeta(L, 1, "__tostring") &&
		    lua_type(L, -1) == LUA_TSTRING)
			return 1;
		else
			msg = lua_pushfstring(L, "(error object is a %s value)",
					      luaL_typename(L, 1));
	}

	luaL_traceback(L, L, msg, 1);
	return 1;
}

static int nflua_pcall(lua_State *L, int nargs, int nresults)
{
	int status;
	int base = lua_gettop(L) - nargs;

	// TODO: Instead of these #ifs we should use monotonic time, which has
	// had the same interface forever. But to avoid inconsistencies,
	// userspace needs to be updated to use monotonic timers as well.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	struct timespec64 start, stop;
#else
	struct timeval start, stop;
#endif

	lua_pushcfunction(L, nflua_msghandler);
	lua_insert(L, base);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	ktime_get_real_ts64(&start);
#else
	do_gettimeofday(&start);
#endif

	status = lua_pcall(L, nargs, nresults, base);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	ktime_get_real_ts64(&stop);
	total_elapsed_time_usec +=
		(unsigned)((stop.tv_nsec - start.tv_nsec) * NSEC_PER_USEC) +
		(unsigned)((stop.tv_sec - start.tv_sec) * USEC_PER_SEC);
#else
	do_gettimeofday(&stop);
	total_elapsed_time_usec += (stop.tv_usec - start.tv_usec) +
				   (stop.tv_sec - start.tv_sec) * USEC_PER_SEC;
#endif

	lua_remove(L, base);
	return status;
}

enum mode { NFLUA_MATCH, NFLUA_TARGET };

union call_result {
	bool match;
	unsigned int verdict;
};

static unsigned int string_to_tg(const char *s)
{
	struct target_pair {
		const char *k;
		int v;
	};
	static struct target_pair targets[] = {
		{ "drop", NF_DROP },	 { "accept", NF_ACCEPT },
		{ "stolen", NF_STOLEN }, { "queue", NF_QUEUE },
		{ "repeat", NF_REPEAT }, { "stop", NF_STOP }
	};
	int i;

	/* TODO: Return integer from lua matching NF_-targets
	 * so we don't need to do this loop.
	 */
	for (i = 0; i < sizeof(targets) / sizeof(*targets); i++)
		if (strcmp(targets[i].k, s) == 0)
			return targets[i].v;

	return XT_CONTINUE;
}

static int nflua_docall(lua_State *L)
{
	struct nflua_ctx *ctx = lua_touserdata(L, 1);
	struct sk_buff *skb = ctx->skb;
	const struct xt_lua_mtinfo *info = ctx->par->matchinfo;
	int error;

	luaU_setregval(L, NFLUA_CTXENTRY, ctx);
	luaU_setregval(L, NFLUA_SKBCLONE, NULL);

	if (lua_getglobal(L, info->func) != LUA_TFUNCTION)
		return luaL_error(L, "couldn't find function: %s\n",
				  info->func);

	if (skb_linearize(skb) != 0)
		return luaL_error(L, "skb linearization failed.\n");

	ctx->frame =
		ldata_newref(L, skb_mac_header(skb), skb_mac_header_len(skb));
	ctx->packet = ldata_newref(L, skb->data, skb->len);
	error = lua_pcall(L, 2, 1, 0);

	luaU_setregval(L, NFLUA_CTXENTRY, NULL);
	luaU_setregval(L, NFLUA_SKBCLONE, NULL);

	if (error)
		return lua_error(L);

	return 1;
}

static union call_result nflua_call(struct sk_buff *skb,
				    struct xt_action_param *par, int mode)
{
	struct nflua_ctx ctx = { .skb = (struct sk_buff *)skb,
				 .par = par,
				 .frame = LUA_NOREF,
				 .packet = LUA_NOREF };
	struct xt_lua_net *xt_lua = xt_lua_pernet(xt_net(par));
	union call_result r;
	int base;
	lua_State *L;

	switch (mode) {
	case NFLUA_MATCH:
		r.match = false;
		break;
	case NFLUA_TARGET:
		r.verdict = XT_CONTINUE;
		break;
	}

	spin_lock(&xt_lua->lock);

	L = xt_lua->L;

	if (L == NULL) {
		pr_err("invalid lua state");
		goto unlock;
	}

	base = lua_gettop(L);
	lua_pushcfunction(L, nflua_docall);
	lua_pushlightuserdata(L, (void *)&ctx);
	if (nflua_pcall(L, 1, 1)) {
		pr_err("%s\n", lua_tostring(L, -1));
		goto cleanup;
	}

	switch (mode) {
	case NFLUA_MATCH:
		if (lua_isboolean(L, -1))
			r.match = lua_toboolean(L, -1);
		else {
			const struct xt_lua_mtinfo *info = par->matchinfo;
			pr_warn("invalid match return: %s", info->func);
		}
		break;
	case NFLUA_TARGET:
		if (lua_isstring(L, -1)) {
			r.verdict = string_to_tg(lua_tostring(L, -1));
			if (r.verdict == NF_STOLEN)
				kfree_skb(skb);
		}
		break;
	}

cleanup:
	ldata_unref(L, ctx.frame);
	ldata_unref(L, ctx.packet);
	lua_settop(L, base);
unlock:
	spin_unlock(&xt_lua->lock);

	return r;
}

static bool nflua_match(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_lua_mtinfo *info = par->matchinfo;

	if (info->mask && !((__u32)atomic_read(&match_mask) & info->mask))
		return false;

	if ((info->flags & XT_NFLUA_TCP_PAYLOAD) &&
	    tcp_payload_length(skb) <= 0)
		return false;

	if (info->func[0] == '\0')
		return true;

	return nflua_call((struct sk_buff *)skb, par, NFLUA_MATCH).match;
}

static unsigned int nflua_target(struct sk_buff *skb,
				 const struct xt_action_param *par)
{
	return nflua_call(skb, (struct xt_action_param *)par, NFLUA_TARGET)
		.verdict;
}

static int nflua_reply(lua_State *L)
{
	size_t len;
	unsigned char *type;
	unsigned char *msg;
	struct nflua_ctx *ctx;

	luaU_getregval(L, NFLUA_CTXENTRY, &ctx);
	if (ctx == NULL)
		goto error;

	type = (unsigned char *)luaL_checkstring(L, 1);
	msg = (unsigned char *)luaL_checklstring(L, 2, &len);

	switch (type[0]) {
	case 't':
		if (tcp_reply(ctx->skb, ctx->par, msg, len) != 0)
			goto error;
		break;
	default:
		goto error;
	}

	return 0;
error:
	return luaL_error(L, "couldn't reply a packet");
}

// the kernel on atom-based puma7 uses a different
// function prototype for nlmsg_unicast
#ifdef CUJO_ATOM_NLMSG_UNICAST
#define nlmsg_unicast(sk, skb, portid) nlmsg_unicast((sk), (skb), (portid), 0)
#endif

#define nlmsg_send(sock, skb, pid, group)               \
	((group == 0) ? nlmsg_unicast(sock, skb, pid) : \
			      nlmsg_multicast(sock, skb, pid, group, 0))

static int nflua_netlink(lua_State *L)
{
	size_t size;
	const char *payload = luaL_checklstring(L, 1, &size);
	int pid = luaL_checkinteger(L, 2);
	int group = luaL_optinteger(L, 3, 0);
	int flags = luaL_optinteger(L, 4, 0);
	int err;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct sock *sock;

	luaU_getregval(L, NFLUA_SOCK, &sock);
	if (sock == NULL)
		return luaL_error(L, "invalid netlink socket");

	skb = nlmsg_new(size, GFP_ATOMIC);
	if (skb == NULL)
		return luaL_error(L, "insufficient memory");

	if ((nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, size, flags)) == NULL) {
		kfree_skb(skb);
		return luaL_error(L, "message too long");
	}

	memcpy(nlmsg_data(nlh), payload, size);

	if ((err = nlmsg_send(sock, skb, pid, group)) < 0) {
		switch (-err) {
		case EAGAIN:
			return luaL_error(L, "socket buffer full: agent busy?");
		case ECONNREFUSED:
			return luaL_error(
				L, "connection refused: agent shut down?");
		default:
			return luaL_error(L, "error code %d", err);
		}
	}

	lua_pushinteger(L, (lua_Integer)size);
	return 1;
}

static int nflua_genetlink(lua_State *L)
{
	size_t size;
	const char *payload = luaL_checklstring(L, 1, &size);
	int pid = luaL_checkinteger(L, 2);
	int err;
	struct sk_buff *skb;
	void *msg_head;

	skb = genlmsg_new(nla_total_size(size), GFP_ATOMIC);
	if (skb == NULL) {
		return luaL_error(L, "insufficient memory");
	}

	msg_head = genlmsg_put(skb, 0, 1, &genl_nflua_family, NLMSG_DONE,
			       GENL_NFLUA_MSG);
	if (msg_head == NULL) {
		kfree_skb(skb);
		return luaL_error(L, "message init failed");
	}

	err = nla_put(skb, GENL_NFLUA_MSG, size, payload);
	if (err != 0) {
		kfree_skb(skb);
		return luaL_error(L, "message too long");
	}

	genlmsg_end(skb, msg_head);

	err = genlmsg_unicast(gennet, skb, pid);
	if (err != 0) {
		switch (-err) {
		case EAGAIN:
			return luaL_error(
				L, "socket buffer full: Userspace busy?");
		case ECONNREFUSED:
			return luaL_error(
				L, "connection refused: Userspace shut down?");
		default:
			return luaL_error(L, "error code %d", err);
		}
	}

	lua_pushinteger(L, (lua_Integer)size);
	return 1;
}

#define NFLUA_SKBUFF "lskb"
#define tolskbuff(L) ((struct sk_buff **)luaL_checkudata(L, 1, NFLUA_SKBUFF))
#define lnewskbuff(L) \
	((struct sk_buff **)lua_newuserdata(L, sizeof(struct sk_buff *)))

static int nflua_skb_send(lua_State *L)
{
	struct sk_buff *nskb, **lskb = tolskbuff(L);
	struct dst_entry *dst;
	size_t len;
	unsigned char *payload;

	if (*lskb == NULL)
		return luaL_error(L, "closed packet");

	payload = (unsigned char *)lua_tolstring(L, 2, &len);
	if (payload != NULL) {
		nskb = tcp_payload(*lskb, payload, len);
		if (nskb == NULL)
			return luaL_error(L, "unable to set tcp payload");

		/* Original packet is not needed anymore */
		kfree_skb(*lskb);
	} else {
		if (unlikely(skb_shared(*lskb)))
			return luaL_error(L, "cannot send a shared skb");
		nskb = *lskb;
	}
	*lskb = NULL;

	dst = skb_dst(nskb);
	if (unlikely(!dst || !dst->dev || !dev_net(dst->dev))) {
		kfree_skb(nskb);
		luaL_error(L, "unable to route packet (device gone?)");
	}
	if (unlikely(!netif_carrier_ok(dst->dev))) {
		kfree_skb(nskb);
		luaL_error(L, "unable to route packet, destination link down");
	}

	if (route_me_harder(dev_net(dst->dev), nskb)) {
		kfree_skb(nskb);
		luaL_error(L, "unable to route packet");
	}

	if (tcp_send(nskb))
		luaL_error(L, "unable to send packet");

	return 0;
}

static int nflua_getpacket(lua_State *L)
{
	struct sk_buff **lskb;
	struct nflua_ctx *ctx;

	luaU_getregval(L, NFLUA_CTXENTRY, &ctx);
	if (ctx == NULL)
		return luaL_error(L, "couldn't get packet context");

	lua_getfield(L, LUA_REGISTRYINDEX, NFLUA_SKBCLONE);
	if (!lua_isuserdata(L, -1)) {
		lskb = lnewskbuff(L);
		if ((*lskb = skb_copy(ctx->skb, GFP_ATOMIC)) == NULL)
			return luaL_error(L, "couldn't copy packet");

		luaL_setmetatable(L, NFLUA_SKBUFF);
		lua_pushvalue(L, -1);
		lua_setfield(L, LUA_REGISTRYINDEX, NFLUA_SKBCLONE);
	}

	return 1;
}

static int nflua_skb_free(lua_State *L)
{
	struct sk_buff **lskb = tolskbuff(L);

	if (*lskb != NULL) {
		kfree_skb(*lskb);
		*lskb = NULL;
	}

	return 0;
}

static int nflua_skb_tostring(lua_State *L)
{
	struct sk_buff *skb = *tolskbuff(L);

	if (skb == NULL) {
		lua_pushliteral(L, "packet closed");
	} else {
		lua_pushfstring(L,
				"packet: { len:%d data_len:%d users:%d "
				"cloned:%d dataref:%d frags:%d }",
				skb->len, skb->data_len,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
				refcount_read(&skb->users),
#else
				atomic_read(&skb->users),
#endif
				skb->cloned,
				atomic_read(&skb_shinfo(skb)->dataref),
				skb_shinfo(skb)->nr_frags);
	}

	return 1;
}

#define NFLUA_TIMER "ltimer"

static int nflua_time(lua_State *L)
{
	struct timespec ts;

	getnstimeofday(&ts);
	lua_pushinteger(L, (lua_Integer)ts.tv_sec);
	lua_pushinteger(L, (lua_Integer)(ts.tv_nsec / NSEC_PER_MSEC));

	return 2;
}

static void __timeout_cb(struct nftimer_ctx *ctx)
{
	struct xt_lua_net *xt_lua = ctx->xt_lua;
	int base;

	spin_lock(&xt_lua->lock);
	if (xt_lua->L == NULL) {
		pr_err("invalid lua state");
		goto out2;
	}
	base = lua_gettop(xt_lua->L);

	/*
        * if we have already called ltimer_destroy for this timer,
        * the lua callback is going to be nil, so we just bail out.
        */
	if (!luaU_getuvalue(xt_lua->L, ctx, LUA_TFUNCTION))
		goto out;

	if (lua_pcall(xt_lua->L, 0, 0, 0) != 0) {
		pr_warn("%s", lua_tostring(xt_lua->L, -1));
		goto out;
	}

out:
	luaU_unregisterudata(xt_lua->L, ctx);
	lua_settop(xt_lua->L, base);
out2:
	spin_unlock(&xt_lua->lock);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void timeout_cb(struct timer_list *t)
{
	struct nftimer_ctx *ctx = from_timer(ctx, t, timer);
	__timeout_cb(ctx);
}
#else
static void timeout_cb(unsigned long data)
{
	__timeout_cb((struct nftimer_ctx *)data);
}
#endif

static int ltimer_create(lua_State *L)
{
	struct nftimer_ctx *ctx;
	unsigned long msecs = luaL_checkinteger(L, 1);

	luaL_checktype(L, 2, LUA_TFUNCTION);

	ctx = lua_newuserdata(L, sizeof(struct nftimer_ctx));
	ctx->xt_lua = luaU_getenv(L, struct xt_lua_net);
	luaL_setmetatable(L, NFLUA_TIMER);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	timer_setup(&ctx->timer, timeout_cb, 0);
#else
	setup_timer(&ctx->timer, timeout_cb, (unsigned long)ctx);
#endif
	if (mod_timer(&ctx->timer, jiffies + msecs_to_jiffies(msecs)))
		return luaL_error(L, "error setting timer");

	luaU_registerudata(L, -1, ctx); /* shouldn't gc context */
	luaU_setuvalue(L, -1, 2); /* store callback */

	return 1;
}

static int ltimer_destroy(lua_State *L)
{
	struct nftimer_ctx *ctx =
		(struct nftimer_ctx *)luaL_checkudata(L, 1, NFLUA_TIMER);
	int base = lua_gettop(L);

	/* the timer callback has already cleaned the context up */
	if (ctx == NULL)
		return 0;

	del_timer(&ctx->timer);

	luaU_unregisterudata(L, ctx);
	lua_settop(L, base);
	return 0;
}

static const luaL_Reg timerlib[] = { { "create", ltimer_create },
				     { "destroy", ltimer_destroy },
				     { NULL, NULL } };

static const luaL_Reg ltimer_ops[] = { { "__gc", ltimer_destroy },
				       { NULL, NULL } };

int luaopen_timer(lua_State *L)
{
	luaL_newmetatable(L, NFLUA_TIMER);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, ltimer_ops, 0);
	lua_pop(L, 1);

	luaL_newlib(L, timerlib);
	return 1;
}
EXPORT_SYMBOL(luaopen_timer);

int nflua_connid(lua_State *L)
{
	struct nflua_ctx *ctx;
	enum ip_conntrack_info info;
	struct nf_conn *conn;

	luaU_getregval(L, NFLUA_CTXENTRY, &ctx);
	if (ctx == NULL)
		return luaL_error(L, "couldn't get packet context");

	conn = nf_ct_get(ctx->skb, &info);

	/* lua_Integer should always be at least as big as uintptr_t, but we
	 * need the intermediate cast to avoid GCC warnings when it is bigger.
	 */
	lua_pushinteger(L, (lua_Integer)(uintptr_t)conn);

	return 1;
}

int nflua_hotdrop(lua_State *L)
{
	struct nflua_ctx *ctx;

	luaU_getregval(L, NFLUA_CTXENTRY, &ctx);
	if (ctx == NULL)
		return luaL_error(L, "couldn't get packet context");

	luaL_checktype(L, -1, LUA_TBOOLEAN);
	ctx->par->hotdrop = lua_toboolean(L, -1);

	return 0;
}

static int nflua_traffic(lua_State *L)
{
	struct nf_conn *ct = NULL;
	const char *msg = NULL;
	struct nf_conn_counter *counters;
	int to, from, i;
	int ret = 0;

	nflua_getdirection(L, 7, &from, &to);
	if ((ct = nflua_findconnid(L)) == NULL) {
		msg = "connid entry not found";
		goto err;
	}

	if ((counters = kpi_nf_conn_acct_find(ct)) == NULL) {
		msg = "counters not found";
		goto err;
	}

	for (i = from; i <= to; i++) {
		lua_pushinteger(L, atomic64_read(&counters[i].packets));
		lua_pushinteger(L, atomic64_read(&counters[i].bytes));
		ret += 2;
	}
	goto out;
err:
	ret = 2;
	lua_pushnil(L);
	lua_pushstring(L, msg);
out:
	if (ct)
		nf_ct_put(ct);
	return ret;
}

static int nflua_get_cpu_mem_info(lua_State *L)
{
	lua_pushinteger(L, (lua_Integer)total_alloc_mem);
	lua_pushinteger(L, (lua_Integer)total_elapsed_time_usec);
	total_elapsed_time_usec = 0;
	return 2;
}

static int nflua_get_match_mask(lua_State *L)
{
	lua_pushinteger(L, atomic_read(&match_mask));
	return 1;
}

static int nflua_reset_match_mask(lua_State *L)
{
	atomic_set(&match_mask, 0);
	return 0;
}

static int nflua_set_match_bit(lua_State *L)
{
	lua_Integer bit;
	bool enable;
	int match_bit;

	bit = luaL_checkinteger(L, 1);
	luaL_argcheck(L, bit >= 0 && bit < sizeof(match_mask) * 8, 1,
		      "bit out of range");
	luaL_checktype(L, 2, LUA_TBOOLEAN);
	enable = lua_toboolean(L, 2);

	match_bit = 1 << bit;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	if (enable)
		atomic_or(match_bit, &match_mask);
	else
		atomic_andnot(match_bit, &match_mask);
#else
	// atomic_set_mask and atomic_clear_mask are not available on all
	// architectures, so we use add and sub instead. Since we're under the
	// Lua state spinlock we shouldn't suffer from TOC-TOU races here.
	if (enable) {
		if (!(atomic_read(&match_mask) & match_bit))
			atomic_add(match_bit, &match_mask);
	} else if (atomic_read(&match_mask) & match_bit)
		atomic_sub(match_bit, &match_mask);
#endif

	return 0;
}

static const luaL_Reg nflua_lib[] = {
	{ "reply", nflua_reply },
	{ "netlink", nflua_netlink },
	{ "genetlink", nflua_genetlink },
	{ "time", nflua_time },
	{ "getpacket", nflua_getpacket },
	{ "connid", nflua_connid },
	{ "hotdrop", nflua_hotdrop },
	{ "traffic", nflua_traffic },
	{ "get_cpu_mem_info", nflua_get_cpu_mem_info },
	{ "get_match_mask", nflua_get_match_mask },
	{ "reset_match_mask", nflua_reset_match_mask },
	{ "set_match_bit", nflua_set_match_bit },
	{ NULL, NULL }
};

static const luaL_Reg nflua_skb_ops[] = { { "send", nflua_skb_send },
					  { "close", nflua_skb_free },
					  { "__gc", nflua_skb_free },
					  { "__tostring", nflua_skb_tostring },
					  { NULL, NULL } };

int luaopen_nf(lua_State *L)
{
	luaL_newmetatable(L, NFLUA_SKBUFF);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, nflua_skb_ops, 0);
	lua_pop(L, 1);

	luaL_newlib(L, nflua_lib);
	return 1;
}
EXPORT_SYMBOL(luaopen_nf);

static struct xt_match nflua_mt_reg __read_mostly = {
	.name = "lua",
	.revision = 0,
	.family = NFPROTO_UNSPEC,
	.match = nflua_match,
	.checkentry = nflua_checkentry,
	.destroy = nflua_destroy,
	.matchsize = sizeof(struct xt_lua_mtinfo),
	.me = THIS_MODULE
};

static struct xt_target nflua_tg_reg __read_mostly = {
	.name = "LUA",
	.revision = 0,
	.family = NFPROTO_UNSPEC,
	.target = nflua_target,
	.checkentry = nflua_tg_checkentry,
	.destroy = nflua_tg_destroy,
	.targetsize = sizeof(struct xt_lua_mtinfo),
	.me = THIS_MODULE
};

#define nflua_dostring(L, b, s, n) \
	(luaL_loadbufferx(L, b, s, n, "t") || nflua_pcall(L, 0, 0))

static void nflua_input(struct sk_buff *skb)
{
	struct net *net = sock_net(skb->sk);
	struct xt_lua_net *xt_lua = xt_lua_pernet(net);
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	const char *script = (const char *)nlmsg_data(nlh);
	const char *name = script;
	int len = nlmsg_len(nlh);
	int namelen = strnlen(name, len);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
#else
	if (!capable(CAP_NET_ADMIN))
#endif
	{
		pr_err("operation not permitted");
		return;
	}

	if (namelen != len) {
		script += namelen + 1;
		len -= namelen + 1;
	}

	spin_lock_bh(&xt_lua->lock);
	if (xt_lua->L == NULL) {
		pr_err("invalid lua state");
		goto out;
	}
	if (nflua_dostring(xt_lua->L, script, len, name) != 0) {
		pr_err("%s\n", lua_tostring(xt_lua->L, -1));
		lua_pop(xt_lua->L, 1); /* error */
	}
out:
	spin_unlock_bh(&xt_lua->lock);
}

static int genl_nflua_rx_msg(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct xt_lua_net *xt_lua = xt_lua_pernet(net);
	const char *script;
	const char *name;
	int len;
	int namelen;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
#else
	if (!capable(CAP_NET_ADMIN))
#endif
	{
		pr_err("operation not permitted");
		return -EPERM;
	}

	if (!info->attrs[GENL_NFLUA_ATTR_MSG]) {
		pr_err("empty message\n");
		return -EINVAL;
	}

	script = (const char *)nla_data(info->attrs[GENL_NFLUA_ATTR_MSG]);
	name = script;
	len = nla_len(info->attrs[GENL_NFLUA_ATTR_MSG]);
	namelen = strnlen(name, len);

	if (namelen != len) {
		script += namelen + 1;
		len -= namelen + 1;
	}

	if (gennet == NULL)
		gennet = genl_info_net(info);

	spin_lock_bh(&xt_lua->lock);
	if (xt_lua->L == NULL) {
		pr_err("invalid lua state");
		goto out;
	}

	if (nflua_dostring(xt_lua->L, script, len, name) != 0) {
		pr_err("%s\n", lua_tostring(xt_lua->L, -1));
		lua_pop(xt_lua->L, 1); /* error */
	}
out:
	spin_unlock_bh(&xt_lua->lock);
	return 0;
}

static void *lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	struct xt_lua_net *xt_lua = ud;
	void *nptr = NULL;

	/* osize doesn't represent the object old size if ptr is NULL */
	osize = ptr != NULL ? osize : 0;

	if (nsize == 0) {
		xt_lua->alloc -= osize;
		kfree(ptr);
	} else if (xt_lua->alloc - osize + nsize > XT_LUA_MEM_LIMIT) {
		pr_warn_ratelimited("memory limit %d exceeded\n",
				    XT_LUA_MEM_LIMIT);
	} else if ((nptr = krealloc(ptr, nsize, GFP_ATOMIC)) != NULL) {
		xt_lua->alloc += nsize - osize;
	}

	total_alloc_mem = xt_lua->alloc;
	return nptr;
}

static struct genl_ops genl_nflua_ops[] = {
	{
		.cmd = GENL_NFLUA_MSG,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
		.policy = genl_nflua_policy,
#endif
		.doit = genl_nflua_rx_msg,
	},
};

static struct genl_family genl_nflua_family = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	.id = GENL_ID_GENERATE,
#endif
	.hdrsize = 0,
	.name = GENL_NFLUA_FAMILY_NAME,
	.version = 1,
	.maxattr = GENL_NFLUA_ATTR_MAX,
	.netnsok = false,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
	.policy = genl_nflua_policy,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	.module = THIS_MODULE,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	.ops = genl_nflua_ops,
	.n_ops = ARRAY_SIZE(genl_nflua_ops),
#endif
};

static int __net_init xt_lua_net_init(struct net *net)
{
	struct xt_lua_net *xt_lua = xt_lua_pernet(net);
	struct sock *sock = NULL;
	int ret;
	lua_State *L;

	unsigned int groups = 0;
	void (*input)(struct sk_buff * skb) = nflua_input;

	if (netlink_family == NETLINK_GENERIC) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
		ret = genl_register_family(&genl_nflua_family);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
		ret = genl_register_family_with_ops(&genl_nflua_family,
						    &genl_nflua_ops[0],
						    ARRAY_SIZE(genl_nflua_ops));
#else
		ret = genl_register_family(&genl_nflua_family);

		if (unlikely(ret < 0)) {
			printk(KERN_ERR
			       "cannot register generic netlink family: %d\n",
			       ret);
			return -EPFNOSUPPORT;
		}

		ret = genl_register_ops(&genl_nflua_family, &genl_nflua_ops[0]);
#endif

		if (ret != 0)
			return -EPFNOSUPPORT;
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
		struct netlink_kernel_cfg cfg = {
			.groups = groups,
			.input = input,
		};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
		sock = netlink_kernel_create(net, NETLINK_NFLUA, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
		sock = netlink_kernel_create(net, NETLINK_NFLUA, THIS_MODULE,
					     &cfg);
#else
		sock = netlink_kernel_create(net, NETLINK_NFLUA, groups, input,
					     NULL, THIS_MODULE);
#endif
		if (sock == NULL)
			return -ENOMEM;
	}

	spin_lock_init(&xt_lua->lock);

	spin_lock_bh(&xt_lua->lock);
	xt_lua->net = net;
	xt_lua->alloc = 0;
	xt_lua->L = L = lua_newstate(lua_alloc, xt_lua);
	if (L == NULL) {
		spin_unlock_bh(&xt_lua->lock);
		netlink_kernel_release(sock);
		return -ENOMEM;
	}

	luaU_setenv(L, xt_lua, struct xt_lua_net);
	luaL_openlibs(L);

	luaL_requiref(L, "nf", luaopen_nf, 1);
	luaL_requiref(L, "timer", luaopen_timer, 1);
	luaL_requiref(L, "data", luaopen_data, 1);
	lua_pop(L, 3);

	/* fixes an issue where the Lua's GC enters a vicious cycle.
	 * more info here: https://marc.info/?l=lua-l&m=155024035605499&w=2
	 */
	lua_gc(L, LUA_GCSETPAUSE, NFLUA_SETPAUSE);

	luaU_setregval(L, NFLUA_SOCK, sock);
	spin_unlock_bh(&xt_lua->lock);

	return 0;
}

static void __net_exit xt_lua_net_exit(struct net *net)
{
	struct xt_lua_net *xt_lua = xt_lua_pernet(net);
	struct sock *sock = NULL;

	spin_lock_bh(&xt_lua->lock);
	if (xt_lua->L != NULL) {
		luaU_getregval(xt_lua->L, NFLUA_SOCK, &sock);
		lua_close(xt_lua->L);
		xt_lua->L = NULL;
	}
	spin_unlock_bh(&xt_lua->lock);

	if (sock != NULL)
		netlink_kernel_release(sock);

	genl_unregister_family(&genl_nflua_family);

	gennet = NULL;
}

static struct pernet_operations xt_lua_net_ops = {
	.init = xt_lua_net_init,
	.exit = xt_lua_net_exit,
	.id = &xt_lua_net_id,
	.size = sizeof(struct xt_lua_net),
};

static int __init xt_lua_init(void)
{
	int ret;

	if (!nf_util_init())
		return -EFAULT;

	if ((ret = register_pernet_subsys(&xt_lua_net_ops)))
		return ret;

	if ((ret = xt_register_match(&nflua_mt_reg))) {
		unregister_pernet_subsys(&xt_lua_net_ops);
		return ret;
	}

	if ((ret = xt_register_target(&nflua_tg_reg))) {
		unregister_pernet_subsys(&xt_lua_net_ops);
		xt_unregister_match(&nflua_mt_reg);
		return ret;
	}

	return ret;
}

static void __exit xt_lua_exit(void)
{
	xt_unregister_match(&nflua_mt_reg);
	xt_unregister_target(&nflua_tg_reg);
	unregister_pernet_subsys(&xt_lua_net_ops);
}

module_init(xt_lua_init);
module_exit(xt_lua_exit);
