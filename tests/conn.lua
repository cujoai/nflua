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

driver.test('conn traffic not found', conntest, [[
	function f(pkt)
		local ip, tcp = util.iptcp(pkt)
		-- src and dst port swapped
		local ok, err = conn.traffic(4, 'tcp', util.toip(ip.src),
			tcp.dport, util.toip(ip.dst), tcp.sport, 'original')
		assert(ok == nil)
		assert(err == 'connid entry not found')
		return true
	end
]])

driver.test('conn traffic invalid arg', conntest, [[
	function f(pkt)
		local ip, tcp = util.iptcp(pkt)
		local args = {4, 'tcp', util.toip(ip.src), tcp.sport,
			util.toip(ip.dst), tcp.dport, 'original'}

		function check(msg, arg, v)
			local finalargs = {table.unpack(args)}
			finalargs[arg] = v
			local finalmsg = string.format(
				"bad argument #%d to 'conn.traffic' (%s)",
				arg, msg)
			local ok, err = pcall(conn.traffic,
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
		check("invalid option 'xxx'", 7, 'xxx')

		return true
	end
]])

driver.test('conn traffic', conntest, string.format([[
	local first = true
	local svaddr = %q

	local packets = {original = 0, reply = 0}
	local bytes = {original = 0, reply = 0}

	function f(pkt)
		local ip, tcp = util.iptcp(pkt)
		local src, dst = util.toip(ip.src), util.toip(ip.dst)
		local sport, dport = tcp.sport, tcp.dport
		local dir = dst == svaddr and 'original' or 'reply'
		packets[dir] = packets[dir] + 1
		bytes[dir] = bytes[dir] + #pkt

		local pkt, b = conn.traffic(4, 'tcp', src, sport, dst, dport, dir)
		if first then
			first = false
			assert(pkt == nil)
			assert(b == 'connid entry not found')
		else
			assert(pkt == packets[dir])
			assert(b == bytes[dir])
			local po, bo, pr, br = conn.traffic(4, 'tcp', src, sport, dst, dport, "both")
			assert(packets.original == po)
			assert(packets.reply == pr)
			assert(bytes.original == bo)
			assert(bytes.reply == br)
		end

		return true
	end
]], network.svaddr))
