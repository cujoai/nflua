--
-- Copyright (C) 2017-2019  CUJO LLC
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
--

util = {}

function util.tomac(n)
	local addr = {}
	for i = 5, 0, -1 do
		table.insert(addr, string.format('%02x', (n >> (i * 8)) & 0xFF))
	end
	return table.concat(addr, ':')
end

function util.toip(n)
	local addr = {}
	for i = 3, 0, -1 do
		table.insert(addr, string.format('%d', (n >> (i * 8)) & 0xFF))
	end
	return table.concat(addr, '.')
end

local macfmt =
	">"..  -- big-endian
	"I6".. -- dst
	"I6".. -- src
	"I2"   -- type

function util.mac(frame)
	local hdr = {}
	hdr.dst, hdr.src, hdr.type = memory.unpack(frame, macfmt)
	return hdr
end

local ipfmt =
	">"..  -- big-endian
	"B"..  -- version(4)+ihl(4)
	"B"..  -- tos(6)+ecn(2)
	"I2".. -- tot_len
	"I2".. -- id
	"I2".. -- flags(3)+frag_off(13)
	"B"..  -- ttl
	"B"..  -- protocol
	"I2".. -- check
	"I4".. -- src
	"I4"   -- dst

local function iplayout(packet)
	local hdr = {}
	local ver_ihl, tos_ecn, flg_off
	ver_ihl,
	tos_ecn,
	hdr.tot_len,
	hdr.id,
	flg_off,
	hdr.ttl,
	hdr.protocol,
	hdr.check,
	hdr.src,
	hdr.dst = packet:unpack(ipfmt)
	hdr.version = (ver_ihl & 0xf0) >> 4
	hdr.ihl = ver_ihl & 0x0f
	hdr.tos = (tos_ecn & 0xfc) >> 2
	hdr.ecn = tos_ecn & 0x03
	hdr.flags = (flg_off & 0xe000) >> 13
	hdr.frag_off = flg_off & 0x1fff
	return hdr
end

local tcpfmt =
	">"..  -- big-endian
	"I2".. -- sport
	"I2".. -- dport
	"I4".. -- seqn
	"I4".. -- ackn
	"B"  -- doff(4)

local function tcplayout(packet, off)
	local hdr = {}
	local doff
	hdr.sport,
	hdr.dport,
	hdr.seqn,
	hdr.ackn,
	doff = packet:unpack(tcpfmt, off)
	hdr.doff = (doff & 0xf0) >> 4
	return hdr
end

function util.iptcp(packet)
	local ip = iplayout(packet)
	local tcp = tcplayout(packet, ip.ihl * 4 + 1)
	local doff = (ip.ihl + tcp.doff) * 4 + 1
	local dlen = (#packet - doff) + 1
	local data = packet:unpack('c'..dlen, doff)
	return ip, tcp, data
end
