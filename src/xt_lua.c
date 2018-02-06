/*
 * This file is Confidential Information of Cujo LLC.
 * Copyright (c) 2017 CUJO LLC. All rights reserved.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/printk.h>

#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/ip.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/kfifo.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <luautil.h>
#include <luadata.h>

#include "xt_lua.h"
#include "nf_util.h"

MODULE_LICENSE("Proprietary. (C) 2017 CUJO LLC.");
MODULE_AUTHOR("Pedro Caldas Tammela <pctammela@getcujo.com>");
MODULE_AUTHOR("Lourival Vieira Neto <lourival.neto@getcujo.com>");
MODULE_AUTHOR("Iruatã Souza <iru@getcujo.com>");

MODULE_DESCRIPTION("Netfilter Lua module");

extern int luaopen_json(lua_State* L);

static lua_State *L = NULL;

static DEFINE_SPINLOCK(lock);

static DEFINE_KFIFO(touser, const char *, 32);

static DECLARE_WAIT_QUEUE_HEAD(waitq);

struct nflua_ctx {
	struct sk_buff *skb;
	struct xt_action_param *par;
};

static void nflua_destroy(const struct xt_mtdtor_param *par)
{
}

static int nflua_checkentry(const struct xt_mtchk_param *par)
{
	return 0;
}

static bool nflua_match(struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_lua_mtinfo *info = par->matchinfo;
	struct nflua_ctx ctx = {.skb = skb, .par = par};
	bool match = false;
	int error  = 0;
	int frame = LUA_NOREF;
	int packet = LUA_NOREF;

	spin_lock(&lock);
	luaU_setenv(L, &ctx, struct nflua_ctx);

	if (lua_getglobal(L, info->func) != LUA_TFUNCTION) {
		pr_err("%s: %s\n", "couldn't find match function", info->func);
		goto out;
	}

	frame = ldata_newref(L, skb_mac_header(skb), skb->mac_len);
	packet = ldata_newref(L, skb->data, skb->len);

	error = lua_pcall(L, 2, 1, 0);

	ldata_unref(L, frame);
	ldata_unref(L, packet);

	if (error) {
		pr_err("%s\n", lua_tostring(L, -1));
		goto out;
	}

	par->hotdrop = (bool) lua_isnil(L, -1); /* cache miss? */
	match = par->hotdrop ? false : (bool) lua_toboolean(L, -1);
out:
	lua_pop(L, 1); /* result, info->func or error */
	spin_unlock(&lock);
	return match;
}

static int nflua_reply(lua_State *L)
{
	size_t len;
	unsigned char *type;
	unsigned char *msg;
	struct nflua_ctx *ctx = luaU_getenv(L, struct nflua_ctx);

	if (ctx == NULL)
		goto error;

	type = (unsigned char *)luaL_checkstring(L, 1);
	msg = (unsigned char *)luaL_checklstring(L, 2, &len);

	switch(type[0]) {
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

static int nflua_touser(lua_State *L)
{
	const char *msg = kstrdup(luaL_checkstring(L, 1), GFP_KERNEL);

	if (msg == NULL || !kfifo_put(&touser, &msg))
		luaL_error(L, "couldn't enqueue message to user space");

	wake_up_interruptible(&waitq);
	return 0;
}

static const luaL_Reg nflua_lib[] = {
	{"reply", nflua_reply},
	{"touser", nflua_touser},
	{NULL, NULL}
};

int luaopen_nf(lua_State *L)
{
	luaL_newlib(L, nflua_lib);
	return 1;
}
EXPORT_SYMBOL(luaopen_nf);

static struct xt_match nflua_mt_reg __read_mostly = {
	.name       = "lua",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = nflua_match,
	.checkentry = nflua_checkentry,
	.destroy    = nflua_destroy,
	.matchsize  = sizeof(struct xt_lua_mtinfo),
	.me         = THIS_MODULE
};

static int nflua_show(struct seq_file *m, void *v)
{
	DEFINE_WAIT(wait);
	struct file *file = m->private;
	int ret = 0;
	const char *msg = NULL;

	while (!kfifo_get(&touser, &msg)) {
		prepare_to_wait(&waitq, &wait, TASK_INTERRUPTIBLE);

		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}

		schedule();
	}
	finish_wait(&waitq, &wait);

	if (msg != NULL) {
		seq_printf(m, "%s", msg);
		kfree(msg);
	}

	return ret;
}

static int nflua_open(struct inode *inode, struct file *file)
{
	return single_open(file, nflua_show, file);
}

#define nflua_dostring(L, b, s)	\
	(luaL_loadbufferx(L, b, s, "nf_lua", "t") ||	\
	 lua_pcall(L, 0, 0, 0))

static ssize_t nflua_write(struct file *file, const char __user *buf,
		size_t size, loff_t *ppos)
{
	char *script = NULL;
	int err_exec = 0;

	if (size == 0)
		return 0;

	script = (char *)kmalloc(size, GFP_KERNEL);
	if (script == NULL)
		return -ENOMEM;

	if (copy_from_user(script, buf, size) < 0)
		return -EIO;

	spin_lock_bh(&lock);
	luaU_setenv(L, NULL, struct nflua_ctx);

	if (nflua_dostring(L, script, size) != 0) {
		pr_err("%s\n", lua_tostring(L, -1));
		lua_pop(L, 1); /* error */
		err_exec = -ENOEXEC;
	}
	spin_unlock_bh(&lock);

	kfree(script);

	return err_exec ? err_exec : size;
}

static int nflua_release(struct inode *inode, struct file *file)
{
	return single_release(inode, file);
}

static const struct file_operations nflua_fops = {
	.owner		= THIS_MODULE,
	.open		= nflua_open,
	.read		= seq_read,
	.write		= nflua_write,
	.llseek		= seq_lseek,
	.release	= nflua_release,
};

static int __init xt_lua_init(void)
{
	spin_lock(&lock);
	L = luaL_newstate();

	if (L == NULL)
		return -ENOMEM;

	luaL_openlibs(L);

	luaL_requiref(L, "nf", luaopen_nf, 1);
	luaL_requiref(L, "data", luaopen_data, 1);
	luaL_requiref(L, "json", luaopen_json, 1);
	lua_pop(L, 3); /* nf, data, json */
	spin_unlock(&lock);

	init_waitqueue_head(&waitq);

	proc_create("nf_lua", 0400, NULL, &nflua_fops);

	return xt_register_match(&nflua_mt_reg);
}

static void __exit xt_lua_exit(void)
{
	const char *msg = NULL;

	spin_lock(&lock);
	if (L != NULL)
		lua_close(L);

	L = NULL;
	spin_unlock(&lock);

	while (kfifo_get(&touser, &msg))
		kfree(msg);

	remove_proc_entry("nf_lua", NULL);

	return xt_unregister_match(&nflua_mt_reg);
}

module_init(xt_lua_init);
module_exit(xt_lua_exit);
