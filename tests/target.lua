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

local baserule = 'iptables -A ' .. network.toclient ..
	' --tcp-flags PSH PSH -j LUA '
local rule = baserule .. ' --state st --function f'
local drop = 'iptables -A ' .. network.toclient ..
	' --tcp-flags PSH PSH -j DROP'

driver.test('target argument state', function ()
	local ok, out = util.pipeexec(baserule .. ' 2>&1')
	assert(ok == nil)
	assert(out:match'"--state" must be specified')
end)

driver.test('target argument function', function ()
	local ok, out = util.pipeexec(baserule .. ' --state st 2>&1')
	assert(ok == nil)
	assert(out:match'"--function" must be specified')
end)

driver.test('target invalid state', function ()
	local ok, out = util.pipeexec(rule .. ' 2>&1')
	assert(ok == nil)
	assert(out:match'No chain/target/match by that name.')
end)

driver.test('target function undefined', function ()
	driver.setup'st'
	util.assertexec(rule)
	network.asserttraffic()
	driver.matchdmesg(4, 'couldn\'t find function: f')
end)

driver.test('target invalid returns', function()
	local c = driver.setup('st')
	util.assertexec(rule)
	for _, case in ipairs{'', '\'continue\'', 'true', 'false', '{}', '1'} do
		driver.run(c, 'execute', 'st', string.format(
		'function f() return %s end', case))
		network.asserttraffic()
	end
end)

driver.test('target yield error', function()
	driver.setup('st', 'function f() error\'oops\' end')
	util.assertexec(rule)
	network.asserttraffic()
end)

driver.test('target veredict accept', function()
	driver.setup('st', 'function f() return \'accept\' end')
	util.assertexec(rule)
	util.assertexec(drop)
	network.asserttraffic()
end)

driver.test('target veredict drop', function()
	driver.setup('st', 'function f() return \'drop\' end')
	util.assertexec(rule)
	network.asserttraffic''
end)

driver.test('target veredict stolen', function()
	driver.setup('st', [[
		function f(pkt)
			timer.create(1, function() pkt:send() end)
			return 'stolen'
		end
	]])
	util.assertexec(rule)
	util.assertexec(drop)
	network.asserttraffic()
end)

driver.test('target veredict repeat-accept', function()
	local token = util.gentoken()
	driver.setup('st', string.format([[
		cnt = 0
		function f()
			cnt = cnt + 1
			if cnt > 1 then print(%q) end
			return cnt > 1 and 'accept' or 'repeat'
		end
	]], token))
	util.assertexec(rule)
	util.assertexec(drop)
	network.asserttraffic()
	driver.matchdmesg(2, token)
end)

driver.test('target veredict repeat-steal', function()
	driver.setup('st', [[
		cnt = 0
		function f(pkt)
			cnt = cnt + 1
			if cnt > 1 then
				timer.create(1, function() pkt:send() end)
				return 'stolen'
			end
			return 'repeat'
		end
	]])
	util.assertexec(rule)
	util.assertexec(drop)
	network.asserttraffic()
end)

driver.test('target veredict tcp reject', function ()
	driver.setup('st', [[
		function f(pkt)
			return 'tcp-reject'
		end
	]])
	util.assertexec(rule)
	network.asserttraffic''
end)
