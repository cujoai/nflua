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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <net/sock.h>

#include <luadata.h>

#include "luautil.h"
#include "netlink.h"
#include "nf_util.h"

#define STATES_PER_FRAG(header)  ((unsigned short)((NFLUA_PAYLOAD_MAXSIZE \
        - NLMSG_SPACE(sizeof(header))) \
        / sizeof(struct nflua_nl_state)))

#define INIT_FRAG_MAX_STATES	STATES_PER_FRAG(struct nflua_nl_list)
#define FRAG_MAX_STATES 	STATES_PER_FRAG(struct nflua_nl_fragment)

#define STATE_OFFSET(hdrptr, hdrsz) \
	((struct nflua_nl_state *)((char *)hdrptr + NLMSG_ALIGN(hdrsz)))

#define DATA_RECV_FUNC "__receive_callback"

struct list_frag {
	struct nflua_nl_state *state;
	unsigned short offset;
	unsigned short total;
};

struct list_cursor {
	struct sock *sock;
	struct nlmsghdr *nlh;
	struct sk_buff *oskb;
	struct list_frag frag;
	unsigned short curr;
	unsigned short total;
};

struct nflua_frag_request {
	char name[NFLUA_NAME_MAXSIZE];
	char script[NFLUA_SCRIPTNAME_MAXSIZE];
	u32 fragseq;
	char *buffer;
	size_t offset;
	size_t total;
	bool release;
};

struct nflua_client {
	struct hlist_node node;
	struct mutex lock;
	struct nflua_frag_request request;
	u32 pid;
	u32 seq;
	u16 msgtype;
};

static u32 hash_random __read_mostly;

#define pid_hash(pid) (jhash_1word(pid, hash_random) & (XT_LUA_HASH_BUCKETS - 1))

static struct nflua_client *client_lookup(struct xt_lua_net *xt_lua, u32 pid)
{
	struct hlist_head *head;
	struct nflua_client *client;

	if (unlikely(xt_lua == NULL))
		return NULL;

	head = &xt_lua->client_table[pid_hash(pid)];
	hlist_for_each_entry_rcu(client, head, node) {
		if (client->pid == pid)
			return client;
	}
	return NULL;
}

static struct nflua_client *client_create(struct xt_lua_net *xt_lua, u32 pid)
{
	struct hlist_head *head;
	struct nflua_client *client;

	if (unlikely(xt_lua == NULL))
		return NULL;

	if ((client = kzalloc(sizeof(struct nflua_client), GFP_ATOMIC)) == NULL)
		return NULL;

	INIT_HLIST_NODE(&client->node);
	mutex_init(&client->lock);
	client->pid = pid;

	head = &xt_lua->client_table[pid_hash(pid)];
	hlist_add_head_rcu(&client->node, head);

	return client;
}

static inline struct nflua_client *client_find_or_create(
		struct xt_lua_net *xt_lua, u32 pid)
{
	struct nflua_client *client = client_lookup(xt_lua, pid);
	if (client == NULL)
		client = client_create(xt_lua, pid);
	return client;
}

static void client_destroy(struct xt_lua_net *xt_lua, u32 pid)
{
	struct nflua_client *client = client_lookup(xt_lua, pid);

	if (unlikely(client == NULL))
		return;

	hlist_del_rcu(&client->node);

	mutex_lock(&client->lock);
	if (client->request.release && client->request.buffer != NULL)
		kfree(client->request.buffer);
	mutex_unlock(&client->lock);

	kfree(client);
}

static int nflua_get_skb(struct sk_buff **skb, u32 seq, u16 type, int flags,
		size_t len, gfp_t alloc)
{
	*skb = nlmsg_new(len, alloc);
	if (*skb == NULL)
		return -ENOMEM;

	if (nlmsg_put(*skb, 0, seq, type, len, flags) == NULL) {
		kfree_skb(*skb);
		return -EMSGSIZE;
	}
	return 0;
}

#define nlmsg_send(sock, skb, pid, group) \
       ((group == 0) ? nlmsg_unicast(sock, skb, pid) : \
               nlmsg_multicast(sock, skb, pid, group, GFP_ATOMIC))

int nflua_nl_send_data(struct nflua_state *s, u32 pid, u32 group,
		const char *payload, size_t len)
{
	struct sk_buff *skb;
	struct nflua_nl_data *data;
	int flags, ret = -1;
	size_t size, hdrsize = NLMSG_ALIGN(sizeof(struct nflua_nl_data));

	if (len > NFLUA_DATA_MAXSIZE)
		return -EMSGSIZE;

	s->dseqnum++;
	flags = NFLM_F_REQUEST | NFLM_F_DONE;
	size = len + hdrsize;

	if ((ret = nflua_get_skb(&skb, s->dseqnum, NFLMSG_DATA, flags,
		size, GFP_ATOMIC)) < 0) {
		pr_err("could not alloc data packet\n");
		return ret;
	}

	data = nlmsg_data((struct nlmsghdr *)skb->data);
	data->total = len;
	memcpy(data->name, s->name, NFLUA_NAME_MAXSIZE);
	memcpy(((char *)data) + hdrsize, payload, len);

	ret = nlmsg_send(s->sock, skb, pid, group);
	return ret < 0 ? ret : 0;
}

static int nflua_create_op(struct xt_lua_net *xt_lua, struct sk_buff *skb)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
	struct nflua_nl_state *cmd = nlmsg_data(nlh);
	struct sk_buff *oskb;
	struct nflua_state *state;
	int ret = -1;

	pr_debug("received NFLMSG_CREATE command\n");

	state = nflua_state_create(xt_lua, cmd->maxalloc, cmd->name);

	if (state == NULL) {
		pr_err("could not create new lua state\n");
		return ret;
	}

	if ((ret = nflua_get_skb(&oskb, nlh->nlmsg_seq, NFLMSG_CREATE,
		NFLM_F_DONE, 0, GFP_KERNEL)) < 0) {
		pr_err("could not alloc replying packet\n");
		return ret;
	}


	pr_debug("new state created: %.*s\n",
		(int)strnlen(cmd->name, NFLUA_NAME_MAXSIZE), cmd->name);

	return nlmsg_unicast(xt_lua->sock, oskb, nlh->nlmsg_pid);
}

static int nflua_destroy_op(struct xt_lua_net *xt_lua, struct sk_buff *skb)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
	struct nflua_nl_destroy * cmd = nlmsg_data(nlh);
	struct sk_buff *oskb;
	int ret = -1;

	pr_debug("received NFLMSG_DESTROY command\n");

	pr_debug("state: %.*s\n",
		(int)strnlen(cmd->name, NFLUA_NAME_MAXSIZE), cmd->name);

	if (nflua_state_destroy(xt_lua, cmd->name)) {
		pr_err("could not destroy lua state\n");
		return ret;
	}

	if ((ret = nflua_get_skb(&oskb, nlh->nlmsg_seq, NFLMSG_DESTROY,
		NFLM_F_DONE, 0, GFP_KERNEL)) < 0) {
		pr_err("could not alloc replying packet\n");
		return ret;
	}

	return nlmsg_unicast(xt_lua->sock, oskb, nlh->nlmsg_pid);
}

static void init_list_hdr(struct list_cursor *lc)
{
	struct nlmsghdr *onlh = (struct nlmsghdr *)lc->oskb->data;
	struct nflua_nl_list *list;
	struct nflua_nl_fragment *frag;

	if (lc->frag.offset == 0) {
		list = nlmsg_data(onlh);
		list->total = lc->total;

		frag = &list->frag;
		frag->seq = 0;

		lc->frag.state =
			STATE_OFFSET(list, sizeof(struct nflua_nl_list));
	} else {
		frag = nlmsg_data(onlh);
		frag->seq = (unsigned int)
			((INIT_FRAG_MAX_STATES - lc->frag.offset)
				/ FRAG_MAX_STATES) + 1;

		lc->frag.state =
			STATE_OFFSET(frag, sizeof(struct nflua_nl_fragment));
	}

	frag->offset = lc->frag.offset;
}

static int init_list_skb(struct list_cursor *lc)
{
	int flags, ret;
	unsigned short missing = lc->total - lc->curr;
	size_t skblen;

	lc->frag.offset = lc->curr;

	if (lc->frag.offset == 0) {
		skblen = NLMSG_ALIGN(sizeof(struct nflua_nl_list));
		flags = NFLM_F_INIT;
		flags |= (lc->total > INIT_FRAG_MAX_STATES) ? NFLM_F_MULTI : 0;
		lc->frag.total = min(missing, INIT_FRAG_MAX_STATES);
	} else {
		skblen = NLMSG_ALIGN(sizeof(struct nflua_nl_fragment));
		flags = NFLM_F_MULTI;
		lc->frag.total = min(missing, FRAG_MAX_STATES);
	}

	flags |= lc->frag.offset + lc->frag.total >= lc->total ? NFLM_F_DONE : 0;

	skblen += sizeof(struct nflua_nl_state) * lc->frag.total;
	if ((ret = nflua_get_skb(&(lc->oskb), lc->nlh->nlmsg_seq, NFLMSG_LIST,
				 flags, skblen, GFP_KERNEL)) < 0) {
		return ret;
	}

	init_list_hdr(lc);

	return 0;
}

static void write_state(struct nflua_state *s, struct list_frag *f,
	unsigned short curr)
{
	struct nflua_nl_state *nl_state = f->state + curr - f->offset;
	size_t namelen = strnlen(s->name, NFLUA_NAME_MAXSIZE);

	memset(nl_state, 0, sizeof(struct nflua_nl_state));
	memcpy(&nl_state->name, s->name, namelen);
	nl_state->maxalloc  = s->maxalloc;
	nl_state->curralloc = s->curralloc;
}

static int list_iter(struct nflua_state *state, unsigned short *data)
{
	struct list_cursor *lc = container_of(data, struct list_cursor, total);
	struct sk_buff *skb;
	int ret;

	if (lc->oskb == NULL && (ret = init_list_skb(lc)) < 0) {
		pr_err("couldn't alloc replying packet\n");
		return ret;
	}

	if (state)
		write_state(state, &lc->frag, lc->curr++);

	if (lc->curr < lc->frag.offset + lc->frag.total)
		return 0;

	skb = lc->oskb;
	lc->oskb = NULL;

	if ((ret = nlmsg_unicast(lc->sock, skb, lc->nlh->nlmsg_pid)) != 0)
		pr_err("couldn't send reply packet. Error: %d\n", ret);

	return ret;
}


static int nflua_list_op(struct xt_lua_net *xt_lua, struct sk_buff *skb)
{
	int ret;
	struct list_cursor lcursor = {
		.sock = xt_lua->sock,
		.nlh = (struct nlmsghdr *)skb->data,
		.oskb = NULL,
		.frag = {NULL, 0, 0},
		.curr = 0,
		.total = 0
	};

	pr_debug("received NFLMSG_LIST command\n");

	ret = nflua_state_list(xt_lua, &list_iter, &lcursor.total);
	if (ret != 0)
		goto out;

	pr_debug("total number of states: %u\n", lcursor.total);
	if (lcursor.total == 0)
		ret = list_iter(NULL, &lcursor.total);

out:
	if (ret != 0)
		pr_err("error listing states\n");

	return ret;
}

static int nflua_doexec(lua_State *L)
{
	int error, buf_ref = LUA_NOREF;
	struct nflua_frag_request *req = lua_touserdata(L, 3);

	lua_pop(L, 1);
	buf_ref = ldata_newref(L, req->buffer, req->total);
	error = lua_pcall(L, 2, 0, 0);
	ldata_unref(L, buf_ref);
	if (error) lua_error(L);

	return 0;
}

static int nflua_exec(struct xt_lua_net *xt_lua, u32 pid,
		struct nflua_client *client)
{
	struct nflua_frag_request *req = &client->request;
	struct nflua_state *s;
	int error = 0;

	if ((s = nflua_state_lookup(xt_lua, client->request.name)) == NULL) {
		pr_err("lua state not found\n");
		return -ENOENT;
	}

	spin_lock_bh(&s->lock);
	if (s->L == NULL) {
		pr_err("invalid lua state");
		error = -ENOENT;
		goto out;
	}

	if (client->msgtype == NFLMSG_DATA) {
		lua_pushcfunction(s->L, nflua_doexec);

		if (lua_getglobal(s->L, DATA_RECV_FUNC) != LUA_TFUNCTION) {
			pr_err("%s: %s\n", "couldn't find receive function",
					DATA_RECV_FUNC);
			lua_pop(s->L, 1); /* doexec */
			error = -ENOENT;
			goto out;
		}

		lua_pushinteger(s->L, pid);
		lua_pushlightuserdata(s->L, req);

		if (luaU_pcall(s->L, 3, 0)) {
			pr_err("%s\n", lua_tostring(s->L, -1));
			lua_pop(s->L, 1);
			error = -EIO;
		}
	} else if ((error = luaU_dostring(s->L, req->buffer, req->total,
					  req->script)) != 0) {
		pr_err("%s\n", lua_tostring(s->L, -1));
		lua_pop(s->L, 1); /* error */
		error = -EIO;
	}
out:
	spin_unlock_bh(&s->lock);
	return error;
}

static int init_request(struct nflua_client *c, size_t total, bool allocate,
		char *buffer)
{
	struct nflua_frag_request *request = &c->request;
	int ret = -EPROTO;

	pr_debug("creating client buffer id: %u size: %ld\n", c->pid, total);

	if (request->buffer != NULL) {
		pr_err("invalid client buffer state\n");
		return ret;
	}

	if (allocate && (buffer = kmalloc(total, GFP_KERNEL)) == NULL) {
		pr_err("could not alloc client buffer\n");
		return -ENOMEM;
	}

	request->offset = 0;
	request->total = total;
	request->buffer = buffer;
	request->release = allocate;

	return 0;
}

static inline void clear_request(struct nflua_client *c)
{
	if (c != NULL) {
		pr_debug("clearing client %u request\n", c->pid);

		if(c->request.release && c->request.buffer != NULL)
			kfree(c->request.buffer);

		memset(&c->request, 0, sizeof(struct nflua_frag_request));
	}
}

static int nflua_reassembly(struct nflua_client *client,
		struct nflua_nl_fragment *frag, size_t len)
{
	struct nflua_frag_request *request = &client->request;
	char *p = ((char *)frag) + NLMSG_ALIGN(sizeof(struct nflua_nl_fragment));

	if (request->offset + len > request->total) {
		pr_err("Invalid message. Current offset: %ld\n"
		       "Packet data length: %ld of total %ld\n",
			request->offset, len, request->total);
		return -EMSGSIZE;
	}

	memcpy(request->buffer + request->offset, p, len);
	request->offset += len;

	return 0;
}

static int nflua_handle_frag(struct xt_lua_net *xt_lua,
		struct nflua_client *client, struct nlmsghdr *nlh,
		struct nflua_nl_fragment *frag, size_t datalen)
{
	struct sk_buff *oskb;
	size_t unfragmax = NFLUA_PAYLOAD_SIZE(sizeof(struct nflua_nl_script));
	int ret;

	if (nlh->nlmsg_flags & NFLM_F_MULTI) {
		if ((ret = nflua_reassembly(client, frag, datalen)) < 0) {
			pr_err("payload assembly error %d\n", ret);
			goto out;
		}

		if (!(nlh->nlmsg_flags & NFLM_F_DONE)) {
			pr_debug("waiting for next fragment\n");
			return 0;
		}

	} else if (client->request.total > unfragmax) {
		pr_err("invalid unfragmented payload size\n");
		ret = -EFAULT;
		goto out;
	}

	if ((ret = nflua_exec(xt_lua, nlh->nlmsg_pid, client)) < 0) {
		pr_err("could not execute / load data!\n");
		goto out;
	}

	if ((ret = nflua_get_skb(&oskb, nlh->nlmsg_seq, NFLMSG_EXECUTE,
				NFLM_F_DONE, 0, GFP_KERNEL)) < 0) {
		pr_err("could not alloc replying packet\n");
		goto out;
	}

	ret = nlmsg_unicast(xt_lua->sock, oskb, nlh->nlmsg_pid);

out:
	clear_request(client);
	return ret;
}

static int nflua_execute_op(struct xt_lua_net *xt_lua, struct sk_buff *skb,
		struct nflua_client *client)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
	struct nflua_nl_script *cmd;
	struct nflua_nl_fragment *frag;
	size_t datalen;

	pr_debug("received NFLMSG_EXECUTE command\n");

	if (nlh->nlmsg_flags & NFLM_F_INIT) {
		if (client->request.fragseq != 0) {
			pr_err("Non expected NFLMSG_EXECUTE init\n");
			return -EPROTO;
		}

		cmd = nlmsg_data(nlh);
		if (cmd->total > NFLUA_SCRIPT_MAXSIZE) {
			pr_err("payload larger than allowed\n");
			return -EMSGSIZE;
		} else if (cmd->frag.seq != 0 || cmd->frag.offset != 0) {
			pr_err("invalid NFLMSG_EXECUTE fragment\n");
			return -EPROTO;
		}

		frag = &cmd->frag;
		datalen = nlh->nlmsg_len
			- NLMSG_SPACE(sizeof(struct nflua_nl_script));

		init_request(client,
			     cmd->total,
			     cmd->total > NFLUA_SCRIPT_FRAG_SIZE,
			     ((char *)nlmsg_data(nlh))
			     + NLMSG_ALIGN(sizeof(struct nflua_nl_script)));

		memcpy(client->request.name, cmd->name, NFLUA_NAME_MAXSIZE);
		memcpy(client->request.script, cmd->script, NFLUA_SCRIPTNAME_MAXSIZE);

	} else {
		frag = nlmsg_data(nlh);
		if ((frag->seq - 1) != client->request.fragseq) {
			pr_err("NFLMSG_EXECUTE fragment out of order\n");
			clear_request(client);
			return -EPROTO;
		} else if (frag->offset != client->request.offset) {
			pr_err("Invalid NFLMSG_EXECUTE message."
			       "Expected offset: %ld but got %d\n",
				client->request.offset, frag->offset);
			clear_request(client);
			return -EMSGSIZE;
		}

		datalen = nlh->nlmsg_len
			- NLMSG_SPACE(sizeof(struct nflua_nl_fragment));

		client->request.fragseq++;
	}

	return nflua_handle_frag(xt_lua, client, nlh, frag, datalen);
}

static int nflua_data_op(struct xt_lua_net *xt_lua, struct sk_buff *skb,
		struct nflua_client *client)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
	struct nflua_nl_data *cmd = nlmsg_data(nlh);
	size_t mlen = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct nflua_nl_data));
	int ret;

	pr_debug("received NFLMSG_DATA command\n");

	if (nlh->nlmsg_flags != (NFLM_F_REQUEST | NFLM_F_DONE)) {
		pr_err("Malformed NFLMSG_DATA\n");
		return -EPROTO;
	}

	if (cmd->total > NFLUA_DATA_MAXSIZE || cmd->total != mlen) {
		pr_err("invalid payload size\n");
		return -EMSGSIZE;
	}

	init_request(client, cmd->total, false,
		((char *)cmd) + NLMSG_ALIGN(sizeof(struct nflua_nl_data)));

	memcpy(client->request.name, cmd->name, NFLUA_NAME_MAXSIZE);

	if ((ret = nflua_exec(xt_lua, nlh->nlmsg_pid, client)) < 0)
		pr_err("could not execute / load data!\n");

	clear_request(client);
	return ret;
}

static inline int nflua_unknown_op(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
	pr_err("received UNKNOWN command type %d\n", nlh->nlmsg_type);
	return -1;
}

static void nflua_handle_error(struct xt_lua_net *xt_lua, struct sk_buff *skb)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
	struct sk_buff *oskb;

	pr_debug("NFLua replying with error\n");

	if (nflua_get_skb(&oskb, nlh->nlmsg_seq, NLMSG_ERROR,
				0, 0, GFP_KERNEL) < 0) {
		pr_err("could not alloc replying packet\n");
		return;
	}

	if (nlmsg_unicast(xt_lua->sock, oskb, nlh->nlmsg_pid) < 0)
		pr_err("could not send error replying packet\n");
}


static void nflua_netlink_input(struct sk_buff *skb)
{
	struct net *net = sock_net(skb->sk);
	struct xt_lua_net *xt_lua = xt_lua_pernet(net);
	struct nlmsghdr *nlh = NULL;
	struct nflua_client *client;
	int result = -1;

	pr_debug("received netlink packet\n");
	if (skb == NULL) {
		pr_err("skb is NULL\n");
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
#else
	if (!capable(CAP_NET_ADMIN))
#endif
	{
		pr_err("operation not permitted\n");
		return;
	}

	nlh = (struct nlmsghdr *)skb->data;
	if ((client = client_find_or_create(xt_lua, nlh->nlmsg_pid)) == NULL) {
		pr_err("could not find or allocate client data\n");
		return;
	}

	mutex_lock(&client->lock);
	if (client->seq == 0 || client->seq + 1 == nlh->nlmsg_seq) {
		client->seq = nlh->nlmsg_seq;
		client->msgtype = nlh->nlmsg_type;
		clear_request(client);
	} else if (client->seq != nlh->nlmsg_seq ||
			!(nlh->nlmsg_flags & NFLM_F_MULTI)){
		pr_err("netlink protocol out of sync\n");
		goto out;
	}

	switch (nlh->nlmsg_type) {
	case NFLMSG_CREATE:
		result = nflua_create_op(xt_lua, skb);
		break;
	case NFLMSG_DESTROY:
		result = nflua_destroy_op(xt_lua, skb);
		break;
	case NFLMSG_LIST:
		result = nflua_list_op(xt_lua, skb);
		break;
	case NFLMSG_EXECUTE:
		result = nflua_execute_op(xt_lua, skb, client);
		break;
	case NFLMSG_DATA:
		result = nflua_data_op(xt_lua, skb, client);
		break;
	default:
		result = nflua_unknown_op(skb);
	}

out:
	if (result < 0)
		nflua_handle_error(xt_lua, skb);

	mutex_unlock(&client->lock);
}

struct urelease_work {
	struct	work_struct w;
	u32	portid;
	struct  xt_lua_net *xt_lua;
};

static void nflua_urelease_event_work(struct work_struct *work)
{
	struct urelease_work *w = container_of(work, struct urelease_work, w);

	pr_debug("release client with pid %u\n", w->portid);
	client_destroy(w->xt_lua, w->portid);

	kfree(w);
}

int nflua_rcv_nl_event(struct notifier_block *this,
				 unsigned long event, void *p)
{
	struct netlink_notify *n = p;
	struct urelease_work *w;

	if (event != NETLINK_URELEASE || n->protocol != NETLINK_NFLUA)
		return NOTIFY_DONE;

	pr_debug("NETLINK_URELEASE event from id %u\n", n->portid);

	if ((w = kmalloc(sizeof(*w), GFP_ATOMIC)) == NULL) {
		pr_err("could not alloc notify work\n");
		return NOTIFY_DONE;
	}

	INIT_WORK((struct work_struct *) w, nflua_urelease_event_work);
	w->portid = n->portid;
	w->xt_lua = xt_lua_pernet(n->net);
	schedule_work((struct work_struct *) w);

	return NOTIFY_DONE;
}

int nflua_netlink_init(struct xt_lua_net *xt_lua, struct net *net)
{
	unsigned int groups = 0;
	void (*input)(struct sk_buff *skb) = nflua_netlink_input;
	int i;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	struct netlink_kernel_cfg cfg = {
		.groups = groups,
		.input = input,
	};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	xt_lua->sock = netlink_kernel_create(net, NETLINK_NFLUA, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	xt_lua->sock = netlink_kernel_create(net, NETLINK_NFLUA, THIS_MODULE,
			&cfg);
#else
	xt_lua->sock = netlink_kernel_create(net, NETLINK_NFLUA, groups, input,
			NULL, THIS_MODULE);
#endif

	if (xt_lua->sock == NULL)
	    return -1;

	spin_lock_init(&xt_lua->client_lock);

	hash_random = get_random_u32();
	for (i = 0; i < XT_LUA_HASH_BUCKETS; i++)
		INIT_HLIST_HEAD(&xt_lua->client_table[i]);

	return 0;
}

void nflua_netlink_exit(struct xt_lua_net *xt_lua)
{
	if (xt_lua->sock != NULL)
		netlink_kernel_release(xt_lua->sock);
}
