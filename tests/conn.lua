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

local driver = require'tests.driver'
local network = require'tests.network'
local util = require'tests.util'

local function conntest(code)
	driver.setup('st', code, true)
	util.assertexec('iptables -A ' .. network.toany ..
		' -m connbytes --connbytes 0 --connbytes-dir both --connbytes-mode bytes')
	util.assertexec('iptables -A ' .. network.toany ..
		' -m lua --state st --function f -j ACCEPT')
	util.assertexec('iptables -A ' .. network.toany .. ' -j DROP')
	network.asserttraffic()
end

driver.test('conn connid', conntest, [[
	local id = nil
	function f(pkt)
		id = id or pkt:connid()
		assert(id ~= nil)
		assert(id == pkt:connid())
		return true
	end
]])

driver.test('conn find', conntest, [[
	local first = true
	function f(pkt)
		local ip, tcp = util.iptcp(pkt:payload())
		local id = conn.find(4, 'tcp', util.toip(ip.src),
			tcp.sport, util.toip(ip.dst), tcp.dport)

		if first then
			first = false
			assert(id == nil)
		else
			assert(id == pkt:connid())
		end

		return true
	end
]])

driver.test('conn find not found', conntest, [[
	function f(pkt)
		local ip, tcp = util.iptcp(pkt:payload())
		-- src and dst port swapped
		local ok, err = conn.find(4, 'tcp', util.toip(ip.src),
			tcp.dport, util.toip(ip.dst), tcp.sport)
		assert(ok == nil)
		assert(err == 'connid entry not found')
		return true
	end
]])

driver.test('conn find invalid arg', conntest, [[
	function f(pkt)
		local ip, tcp = util.iptcp(pkt:payload())
		local args = {4, 'tcp', util.toip(ip.src), tcp.sport,
			util.toip(ip.dst), tcp.dport}

		function check(msg, arg, v)
			local finalargs = {table.unpack(args)}
			finalargs[arg] = v
			local finalmsg = string.format(
				"bad argument #%d to 'conn.find' (%s)",
				arg, msg)
			local ok, err = pcall(conn.find,
				table.unpack(finalargs))
			assert(ok == false)
			print(err, finalmsg)
			assert(err == finalmsg)
		end

		for i = 1, #args do
			check(type(args[i]) .. ' expected, got table', i, {})
			check(type(args[i]) .. ' expected, got boolean', i,
				false)
		end
		check('unknown family', 1, 5)
		check("invalid option 'xxx'", 2, 'xxx')
		for _, i in ipairs{3, 5} do
			check('failed to convert address to binary', i, 'xxx')
			check('failed to convert address to binary', i,
				'10.0.0.256')
		end
		for _, i in ipairs{4, 6} do
			check('invalid port', i, 0)
			check('invalid port', i, -1)
			check('invalid port', i, 65536)
		end

		return true
	end
]])

driver.test('conn traffic', conntest, string.format([[
	local svaddr = %q

	local packets = {original = 0, reply = 0}
	local bytes = {original = 0, reply = 0}

	function f(pkt)
		local payload = pkt:payload()
		local ip = util.iptcp(payload)
		local dir = util.toip(ip.dst) == svaddr and 'original' or 'reply'
		packets[dir] = packets[dir] + 1
		bytes[dir] = bytes[dir] + #payload

		local pkt, b = conn.traffic(pkt:connid(), dir)
		assert(pkt == packets[dir])
		assert(b == bytes[dir])

		return true
	end
]], network.svaddr))

driver.test('conn traffic invalid param', conntest, [[
	function f(pkt)
		local ok, err = pcall(conn.traffic, nil, 'original')
		assert(ok == false)
		assert(err == "bad argument #1 to 'conn.traffic' (invalid connid)")

		local ok, err = pcall(conn.traffic, pkt:connid(), 'xxx')
		assert(ok == false)
		assert(err == "bad argument #2 to 'conn.traffic' (invalid option 'xxx')")

		return true
	end
]])
