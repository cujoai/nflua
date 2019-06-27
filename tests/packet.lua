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

local timeout = 10 -- ms

local methods = {
	'close',
	'connid',
	'frame',
	'payload',
	'send',
	'tcpreply',
}

local function afterreturn(fname)
	local code = string.format([[
		local timeout, fname = %d, %q
		function f(pkt)
			timer.create(timeout, function()
				pkt[fname](pkt)
			end)
			return 'continue'
		end
	]], timeout, fname)
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic()
	util.assertexec('sleep %f', timeout / 1000)
	driver.matchdmesg(3, 'closed packet')
end

for _, f in ipairs(methods) do
	driver.test('packet not stolen then ' .. f, afterreturn, f)
end

driver.test('packet close', function()
	local token = util.gentoken()
	local code = string.format([[
		local timeout, token = %d, %q
		function f(pkt)
			timer.create(timeout, function()
				local ok = pkt:close()
				print(token .. tostring(ok))
			end)
			return 'stolen'
		end
	]], timeout, token)
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic('')
	util.assertexec('sleep %f', timeout / 1000)
	driver.matchdmesg(2, token .. 'true')
end)

driver.test('packet close before stolen', function()
	local code = [[
		function f(pkt)
			pkt:close()
			return 'stolen'
		end
	]]
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic()
	driver.matchdmesg(3, 'packet must be stolen')
end)

driver.test('packet close not stolen', function()
	local code = string.format([[
		local timeout = %d
		function f(pkt)
			timer.create(timeout, function()
				pkt:close()
			end)
			return 'continue'
		end
	]], timeout)
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic()
	util.assertexec('sleep %f', timeout / 1000)
	driver.matchdmesg(1, 'closed packet')
end)

local function afterclose(fname)
	local code = string.format([[
		local timeout, fname = %d, %q
		function f(pkt)
			timer.create(timeout, function()
				pkt:close()
				pkt[fname](pkt)
			end)
			return 'stolen'
		end
	]], timeout, fname)
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic('')
	util.assertexec('sleep %f', timeout / 1000)
	driver.matchdmesg(3, 'closed packet')
end

for _, f in ipairs(methods) do
	driver.test('packet close then ' .. f, afterclose, f)
end

driver.test('packet frame', function()
	local token = util.gentoken()
	local code = string.format([[
		local token = %q
		function f(pkt)
			local mac = util.mac(pkt:frame())
			print(token .. util.tomac(mac.src))
			return 'continue'
		end
	]], token)
	driver.setup('st', code, true)
	util.assertexec(targetrule)
	network.asserttraffic()
	driver.matchdmesg(2, token .. network.svmac())
end)

driver.test('packet payload', function()
	local code = [[
		function f(pkt)
			local ip, tcp, data = util.iptcp(pkt:payload())
			print(util.toip(ip.src) .. tcp.sport .. data)
			return 'continue'
		end
	]]
	driver.setup('st', code, true)
	util.assertexec(targetrule)
	local token = util.gentoken()
	network.asserttraffic(token, token)
	driver.matchdmesg(3, network.svaddr .. network.svport .. token)
end)

driver.test('packet mem unref', function()
	local token = util.gentoken()
	local code = string.format([[
		local timeout, token = %d, %q
		function f(pkt)
			local frame, payload = pkt:frame(), pkt:payload()
			timer.create(timeout, function()
				print(token .. #frame .. #payload)
			end)
			return 'continue'
		end
	]], timeout, token)
	driver.setup('st', code, true)
	util.assertexec(targetrule)
	network.asserttraffic()
	util.assertexec('sleep %f', timeout / 1000)
	driver.matchdmesg(2, token .. 0 .. 0)
end)

driver.test('packet send', function()
	local token = util.gentoken()
	local code = string.format([[
		local timeout, token = %d, %q
		function f(pkt)
			timer.create(timeout, function()
				local ok = pkt:send()
				print(token .. tostring(ok))
			end)
			return 'stolen'
		end
	]], timeout, token)
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic()
	util.assertexec('sleep %f', timeout / 1000)
	driver.matchdmesg(2, token .. 'true')
end)

driver.test('packet send payload', function()
	local token = util.gentoken()
	local code = string.format([[
		local timeout, token = %d, %q
		function f(pkt)
			timer.create(timeout, function()
				local ok = pkt:send(token .. '\n')
				print(token .. tostring(ok))
			end)
			return 'stolen'
		end
	]], timeout, token)
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic(token)
	util.assertexec('sleep %f', timeout / 1000)
	driver.matchdmesg(2, token .. 'true')
end)

driver.test('packet send before stolen', function()
	local code = [[
		function f(pkt)
			pkt:send()
			return 'stolen'
		end
	]]
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic()
	driver.matchdmesg(3, 'packet must be stolen')
end)

local function aftersend(fname)
	local code = string.format([[
		local timeout, fname = %d, %q
		function f(pkt)
			timer.create(timeout, function()
				pkt:send()
				pkt[fname](pkt)
			end)
			return 'stolen'
		end
	]], timeout, fname)
	driver.setup('st', code)
	util.assertexec(targetrule)
	network.asserttraffic()
	util.assertexec('sleep %f', timeout / 1000)
	driver.matchdmesg(3, 'closed packet')
end

for _, f in ipairs(methods) do
	driver.test('packet send then ' .. f, aftersend, f)
end

driver.test('packet tcpreply', function ()
	local token = util.gentoken()
	local code = string.format([[
		function f(pkt)
			pkt:tcpreply(%q .. '\n')
			return true
		end
	]], token)
	driver.setup('st', code)
	util.assertexec(matchrule)
	network.asserttraffic(token)
end)
