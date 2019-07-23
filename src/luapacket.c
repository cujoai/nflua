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
#include <linux/inet.h>
#include <linux/export.h>

#include <lua.h>
#include <lauxlib.h>

#include <lmemlib.h>

#include "kpi_compat.h"
#include "luapacket.h"
#include "luautil.h"
#include "nf_util.h"
#include "states.h"
#include "xt_lua.h"

struct luapacket {
	struct sk_buff *skb;
	int hooknum;
	void *frame;
	bool stolen;
};

#define LUAPACKET "luapacket"

static void makememref(lua_State *L, void **ref, void *data, size_t len)
{
	if (*ref != NULL) {
		luaU_pushudata(L, *ref);
		return;
	}
	luamem_newref(L);
	luamem_setref(L, -1, data, len, NULL);
	*ref = lua_touserdata(L, -1);
	luaU_registerudata(L, -1);
}

static void unrefmem(lua_State *L, void *ref)
{
	if (ref == NULL)
		return;

	luaU_pushudata(L, ref);
	luamem_setref(L, -1, NULL, 0, NULL);
	lua_pop(L, 1);

	luaU_unregisterudata(L, ref);
}

static void unrefpacket(lua_State *L, struct luapacket *p)
{
	unrefmem(L, p->frame);
	memset(p, 0, sizeof(*p));
}

void luapacket_new(lua_State *L, struct sk_buff *skb, int hooknum)
{
	struct luapacket *p = lua_newuserdata(L, sizeof(*p));

	luaL_setmetatable(L, LUAPACKET);
	p->skb = skb;
	p->hooknum = hooknum;
	p->frame = NULL;
	p->stolen = false;
}

void luapacket_stolen(lua_State *L, int arg)
{
	struct luapacket *packet = luaL_checkudata(L, 1, LUAPACKET);

	packet->stolen = true;
}

void luapacket_unref(lua_State *L, int arg)
{
	struct luapacket *packet = luaL_checkudata(L, 1, LUAPACKET);

	unrefpacket(L, packet);
}

static struct luapacket *getpacket(lua_State *L)
{
	struct luapacket *packet = luaL_checkudata(L, 1, LUAPACKET);

	if (packet->skb == NULL)
		luaL_argerror(L, 1, "closed packet");

	return packet;
}

static int luapacket_close(lua_State *L)
{
	struct luapacket *packet = getpacket(L);

	if (!packet->stolen)
		return luaL_error(L, "packet must be stolen");

	kfree_skb(packet->skb);
	unrefpacket(L, packet);
	lua_pushboolean(L, true);

	return 1;
}

static int luapacket_frame(lua_State *L)
{
	struct luapacket *packet = getpacket(L);

	makememref(L, &packet->frame, skb_mac_header(packet->skb),
	           kpi_skb_mac_header_len(packet->skb));

	return 1;
}

static int luapacket_tcpreply(lua_State *L)
{
	struct luapacket *packet = getpacket(L);
	size_t len;
	const unsigned char *msg = luaL_checklstring(L, 2, &len);

	if (tcp_reply(packet->skb, packet->hooknum, msg, len) != 0)
		return luaU_pusherr(L, "couldn't reply a packet");

	lua_pushboolean(L, true);

	return 1;
}

static int luapacket_send(lua_State *L)
{
	struct luapacket *packet = getpacket(L);
	struct sk_buff *nskb = packet->skb;
	const unsigned char *payload;
	size_t len;

	if (!packet->stolen)
		return luaL_error(L, "packet must be stolen");

	payload = lua_tolstring(L, 2, &len);
	if (payload != NULL) {
		nskb = tcp_payload(packet->skb, payload, len);
		if (nskb == NULL)
			return luaU_pusherr(L, "unable to set tcp payload");

		/* Original packet is not needed anymore */
		kfree_skb(packet->skb);
	} else {
		if (unlikely(skb_shared(packet->skb)))
			return luaU_pusherr(L, "cannot send a shared skb");
		nskb = packet->skb;
	}
	unrefpacket(L, packet);

	if (route_me_harder(nskb)) {
		kfree_skb(nskb);
		return luaU_pusherr(L, "unable to route packet");
	}

	if (tcp_send(nskb))
		return luaU_pusherr(L, "unable to send packet");

	lua_pushboolean(L, true);

	return 1;
}

static int luapacket_connid(lua_State *L)
{
	struct luapacket *packet = getpacket(L);
	enum ip_conntrack_info info;
	struct nf_conn *conn;

	conn = nf_ct_get(packet->skb, &info);
	lua_pushlightuserdata(L, conn);

	return 1;
}

static int luapacket_gc(lua_State *L)
{
	struct luapacket *packet = luaL_checkudata(L, 1, LUAPACKET);

	if (packet->skb == NULL)
		return 0;

	if (packet->stolen)
		kfree_skb(packet->skb);

	unrefpacket(L, packet);

	return 0;
}

static int luapacket_tostring(lua_State *L)
{
	struct luapacket *packet = getpacket(L);
	struct sk_buff *skb = packet->skb;

	lua_pushfstring(L,
		"packet: { len:%d data_len:%d users:%d "
		"cloned:%d dataref:%d frags:%d }",
		skb->len,
		skb->data_len,
		kpi_skb_users(skb),
		skb->cloned,
		atomic_read(&skb_shinfo(skb)->dataref),
		skb_shinfo(skb)->nr_frags);

	return 1;
}

static int luapacket_len(lua_State *L)
{
	struct luapacket *packet = getpacket(L);
	struct sk_buff *skb = packet->skb;

	lua_pushinteger(L, skb->len);

	return 1;
}

static int luapacket_unpack(lua_State *L);

static const luaL_Reg luapacket_mt[] = {
	{"close", luapacket_close},
	{"frame", luapacket_frame},
	{"tcpreply", luapacket_tcpreply},
	{"send", luapacket_send},
	{"connid", luapacket_connid},
	{"__gc", luapacket_gc},
	{"__tostring", luapacket_tostring},
	{"__len", luapacket_len},
	{"unpack", luapacket_unpack},
	{NULL, NULL}
};

int luaopen_packet(lua_State *L)
{
	luaL_newmetatable(L, LUAPACKET);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, luapacket_mt, 0);
	return 1;
}
EXPORT_SYMBOL(luaopen_packet);

#include "lua/lstrlib.c"
