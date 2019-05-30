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

local targetrule = 'iptables -A ' .. network.toclient ..
	' --tcp-flags PSH PSH -j LUA --state st --function f'
local matchrule = 'iptables -A ' .. network.toserver ..
	' -m lua --tcp-payload --state st --function f -j DROP'

driver.test('packet close', function()
	local code = [[
		function f()
			local packet = nf.getpacket()
			packet:close()
			return 'stolen'
		end
	]]
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic('')
end)

local function afterclose(fname)
	local code = string.format([[
		function f()
			local packet = nf.getpacket()
			packet:close()
			packet[%q](packet)
			return 'stolen'
		end
	]], fname)
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic('')
	driver.matchdmesg(3, 'closed packet')
end

local cases = {
	'send',
	'close',
}

for _, case in ipairs(cases) do
	driver.test('packet close after ' .. case, afterclose, case)
end

driver.test('packet send', function()
	local code = [[
		function f()
			nf.getpacket():send()
			return 'stolen'
		end
	]]
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic()
end)

driver.test('packet send payload', function()
	local token = util.gentoken()
	local code = string.format([[
		function f()
			nf.getpacket():send(%q .. '\n')
			return 'stolen'
		end
	]], token)
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic(token)
end)

driver.test('packet send timer', function()
	local code = [[
		function f()
			local packet = nf.getpacket()
			timer.create(1, function()
				packet:send()
			end)
			return 'stolen'
		end
	]]
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic()
end)

driver.test('packet send not stolen', function()
	local code = [[
		function f()
			local packet = nf.getpacket()
			timer.create(1, function()
				packet:send()
			end)
			return 'drop'
		end
	]]
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic()
end)

driver.test('packet send twice', function()
	local code = [[
		function f()
			local packet = nf.getpacket()
			packet:send()
			packet:send()
			return 'stolen'
		end
	]]
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic()
	driver.matchdmesg(3, 'closed packet')
end)

driver.test('packet send match', function ()
	local token = util.gentoken()
	local code = string.format([[
		function f()
			nf.getpacket():send()
			return true
		end
	]], token)
	driver.setup('st', code)
	util.assertexec(matchrule)
	network.asserttraffic()
	driver.matchdmesg(3, 'not on target context')
end)

driver.test('packet tcpreply', function ()
	local token = util.gentoken()
	local code = string.format([[
		function f()
			nf.reply('tcp', %q .. '\n')
			return true
		end
	]], token)
	driver.setup('st', code)
	util.assertexec(matchrule)
	network.asserttraffic(token)
end)

driver.test('packet contents', function ()
	local token = util.gentoken()
	local code = string.format([[
		local token, svmac, svaddr, svport = %q, %q, %q, %d

		function f(frame, payload)
			local mac = util.mac(frame)
			assert(util.tomac(mac.dst) == svmac)

			local ip, tcp, data = util.iptcp(payload)
			assert(ip.version == 4)
			assert(util.toip(ip.dst) == svaddr)
			assert(tcp.dport == svport)
			assert(token .. '\n' == tostring(data))

			return true
		end
	]], token, network.svmac(), network.svaddr, network.svport)
	driver.setup('st', code, true)
	util.assertexec(matchrule)
	network.asserttraffic('', token)
end)
