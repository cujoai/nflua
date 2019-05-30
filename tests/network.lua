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

local util = require'tests.util'

local network = {}

local timeout = 0.5 -- seconds

local prefix = 'nflua_'
local svnet = prefix .. 'svnet'
local clnet = prefix .. 'clnet'
local eth0 = prefix .. 'eth0'
local wan0 = prefix .. 'wan0'
local lan0 = prefix .. 'lan0'
local br0 = prefix .. 'br0'

local svaddr = '10.0.33.1'
local wan0addr = '10.0.33.2'
local claddr = '10.0.34.2'
local lan0addr = '10.0.34.1'

local chain = 'NFLUA_TEST_FORWARD'
local jmprule = 'FORWARD -j ' .. chain

network.svaddr = svaddr
network.svport = 12345

network.toserver = string.format('%s -i %s -d %s -p tcp', chain, br0, svaddr)
network.toclient = string.format('%s -i %s -d %s -p tcp', chain, br0, claddr)

function network.svmac()
	local _, out = assert(util.pipeexec('ip -n %s link show %s', svnet,
		eth0))
	return string.match(out, string.rep('%w%w', 6, ':'))
end

local function createnet(netname, addr, iface)
	util.assertexec('ip netns add %s', netname)
	util.assertexec('ip link add %s netns %s type veth peer name %s',
		eth0, netname, iface)

	util.assertexec('ip link set %s up', iface)
	util.assertexec('ip -n %s link set %s up', netname, eth0)

	util.assertexec('ip -n %s addr add %s/24 dev %s', netname, addr, eth0)
	util.assertexec('ip -n %s route add default via %s', netname, addr)
end

function network.setup()
	createnet(svnet, svaddr, wan0)
	createnet(clnet, claddr, lan0)

	util.assertexec('ip link add name %s type bridge', br0)
	util.assertexec('ip link set %s up', br0)
	util.assertexec('ip link set %s master %s', wan0, br0)
	util.assertexec('ip link set %s master %s', lan0, br0)
	util.assertexec('ip addr add %s/24 dev %s', wan0addr, wan0)
	util.assertexec('ip addr add %s/24 dev %s', lan0addr, br0)

	util.assertexec'modprobe br_netfilter'
	util.assertexec'echo 1 > /proc/sys/net/ipv4/ip_forward'

	util.assertexec('iptables -N %s', chain)
	util.assertexec('iptables -I %s', jmprule)
end

function network.cleanup()
	util.silentexec('ip netns del %s', svnet)
	util.silentexec('ip netns del %s', clnet)
	util.silentexec('ip link del %s', wan0)
	util.silentexec('ip link del %s', lan0)
	util.silentexec('ip link del %s', br0)

	util.silentexec'rmmod br_netfilter'
	util.silentexec'echo 0  > /proc/sys/net/ipv4/ip_forward'

	util.silentexec('iptables -D %s', jmprule)
	util.silentexec('iptables -F %s', chain)
	util.silentexec('iptables -X %s', chain)
end

function network.flush()
	util.assertexec('iptables -F %s', chain)
end

local function gentraffic(data)
	util.assertexec('ip netns exec %s lua tests/server.lua %q %q %q &',
		svnet, network.svaddr, network.svport, timeout)
	util.assertexec('sleep %q', timeout)
	local _, out = assert(util.pipeexec(
		'ip netns exec %s lua tests/client.lua %q %q %q %q',
		clnet, network.svaddr, network.svport, timeout, data))
	util.assertexec('sleep %q', timeout)
	return out
end

function network.asserttraffic(output, input)
	input = input or util.gentoken()
	output = output or input
	assert(gentraffic(input) == output)
end

return network
