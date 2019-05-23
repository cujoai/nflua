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

local iface = 'lo'
local chain = 'NFLUA_TEST_INPUT'
local jmprule = 'INPUT -j ' .. chain

network.svaddr = '127.0.0.1'
network.svport = 12345

network.toserver = string.format('%s -i %s -d %s -p tcp --dport %s',
	chain, iface, network.svaddr, network.svport)

function network.setup()
	util.assertexec('iptables -N %s', chain)
	util.assertexec('iptables -I %s', jmprule)
end

function network.cleanup()
	util.silentexec('iptables -D %s', jmprule)
	util.silentexec('iptables -F %s', chain)
	util.silentexec('iptables -X %s', chain)
end

function network.flush()
	util.assertexec('iptables -F %s', chain)
end

function network.gentraffic(data)
	util.assertexec('lua tests/server.lua %q %q %q &', network.svaddr,
		network.svport, timeout)
	util.assertexec('sleep %q', timeout)
	local _, out = assert(util.pipeexec('lua tests/client.lua %q %q %q %q',
		network.svaddr, network.svport, timeout, data))
	util.assertexec('sleep %q', timeout)
	return out
end

function network.asserttraffic()
	local token = util.gentoken()
	assert(network.gentraffic(token) == token)
end

function network.assertnotraffic()
	assert(network.gentraffic(util.gentoken()) == '')
end

return network
