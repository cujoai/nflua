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

local baserule = 'iptables -A ' .. network.toserver .. ' -m lua '

driver.test('match arguments errors', function ()
	local cmd = baserule .. ' %s 2>&1'

	local ok, out = util.pipeexec(cmd, '')
	assert(ok == nil)
	assert(out:match'\'--state\' is mandatory')

	ok, out = util.pipeexec(cmd, '--state st')
	assert(ok == nil)
	assert(out:match'\'--function\' is mandatory')

	ok, out = util.pipeexec(cmd, '--state ' .. ('a'):rep(64))
	assert(ok == nil)
	assert(out:match'\'--state\' is too long')

	ok, out = util.pipeexec(cmd, '--function ' .. ('a'):rep(64))
	assert(ok == nil)
	assert(out:match'\'--function\' is too long')
end)

driver.test('match state does not exist', function ()
	local cmd = baserule .. '--state st --function f 2>&1'
	local ok, out = util.pipeexec(cmd)
	assert(ok == nil)
	assert(out:match('Operation not permitted'))
end)

driver.test('match against undefined function', function ()
	driver.setup'st'
	util.assertexec(baserule .. '--state st --function f')
	network.asserttraffic()
	driver.matchdmesg(4, 'couldn\'t find function: f')
end)

driver.test('match against traffic', function ()
	local token = util.gentoken()
	local code = string.format([[
		function f()
			print(%q)
			return false
		end
	]], token)
	driver.setup('st', code)
	util.assertexec(baserule .. '--state st --function f')
	network.asserttraffic()
	driver.matchdmesg(2, token)
end)

driver.test('match valid return values', function ()
	local c = driver.setup'st'
	util.assertexec(baserule .. '--state st --function f -j DROP')

	local cases = {
		{drop = false, code = 'function f() return false end'},
		{drop = true,  code = 'function f() return true end'},
		{drop = true,  code = 'function f() return "hotdrop" end'},
	}
	for _, case in ipairs(cases) do
		driver.run(c, 'execute', 'st', case.code)
		if case.drop then
			network.assertnotraffic()
		else
			network.asserttraffic()
		end
	end
end)

driver.test('match invalid return values', function ()
	local c = driver.setup'st'
	util.assertexec(baserule .. '--state st --function f -j DROP')

	local cases = {
		'function f() return nil end',
		'function f() return "hotdrox" end',
		'function f() return {} end',
	}
	for _, case in ipairs(cases) do
		driver.run(c, 'execute', 'st', case)
		network.asserttraffic()
		driver.matchdmesg(1, 'invalid match return')
	end
end)

driver.test('match error', function ()
	local token = util.gentoken()
	local code = string.format([[function f() error(%q) end]], token)
	driver.setup('st', code)
	util.assertexec(baserule .. '--state st --function f -j DROP')
	network.asserttraffic()
	driver.matchdmesg(3, token)
end)

driver.test('match tcp payload', function ()
	local code = [[
		local m = 0
		function f()
			m = m + 1
			print(string.format('number of matches: %d', m))
			return true
		end
	]]
	driver.setup('st', code)
	util.assertexec(baserule .. '--state st --tcp-payload --function f')
	network.asserttraffic()
	driver.matchdmesg(2, 'number of matches: 1')
end)
