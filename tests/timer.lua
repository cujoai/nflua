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

local nflua = require'nflua'

local driver = require'tests.driver'
local util = require'tests.util'

local basetimeout = 100 -- ms
local errlimit = 50 -- ms

driver.test('timer create single', function()
	local d = assert(nflua.data())
	local code = string.format([[
		local basetimeout, pid = %d, %d
		local _, old = os.time()
		timer.create(basetimeout, function()
			local _, now = os.time()
			netlink.send(pid, nil, tostring(now - old))
		end)
	]], basetimeout, d:getpid())

	driver.setup('st', code)

	local elapsed = tonumber(tostring(driver.datareceive(d))) / 1000000
	assert(elapsed >= basetimeout)
	assert(elapsed < basetimeout + errlimit)
end)

driver.test('timer create multiple', function()
	local d = assert(nflua.data())
	local n = 3
	local tokens = {}
	for i = 1, n do
		table.insert(tokens, util.gentoken(32))
	end

	local code = string.format([[
		local basetimeout, pid, n, tokens = %d, %d, %d, {"%s"}
		for i = 1, n do
			timer.create((n - i) * basetimeout, function()
				netlink.send(pid, nil, tokens[i])
			end)
		end
	]], basetimeout, d:getpid(), n, table.concat(tokens, '","'))

	driver.setup('st', code)

	for i = n, 1, -1 do
		assert(tostring(driver.datareceive(d)) == tokens[i])
	end
end)

driver.test('timer destroy then close state', function()
	local token = util.gentoken()
	local code = string.format([[
		local timeout, token = %d, %q
		local t = timer.create(timeout, function() end)
		local ok = timer.destroy(t)
		print(token .. tostring(ok))
	]], basetimeout, token)

	local c = driver.setup('st', code)

	driver.run(c, 'destroy', 'st')
	driver.matchdmesg(2, token .. 'true')
end)

driver.test('timer destroy then close module', function()
	local token = util.gentoken()
	local code = string.format([[
		local timeout, token = %d, %q
		local t = timer.create(timeout, function() end)
		local ok = timer.destroy(t)
		print(token .. tostring(ok))
	]], basetimeout, token)

	local c = driver.setup('st', code)

	c:close()
	driver.reloadmodule()
	driver.matchdmesg(2, token .. 'true')
end)

driver.test('timer destroy after callback', function()
	local d = assert(nflua.data())
	local token = util.gentoken(32)
	local code = string.format([[
		local basetimeout, pid, token = %d, %d, %q
		local t
		t = timer.create(basetimeout, function()
			local ok, err = timer.destroy(t)
			assert(ok == nil)
			assert(err == "timer already destroyed")
			netlink.send(pid, nil, token)
		end)
	]], basetimeout, d:getpid(), token)

	driver.setup('st', code)

	assert(tostring(driver.datareceive(d)) == token)
end)

driver.test('timer destroy before callback', function()
	local d = assert(nflua.data())
	local token = util.gentoken(32)
	local code = string.format([[
		local basetimeout, pid, token = %d, %d, %q
		local t = timer.create(basetimeout, function()
			netlink.send(pid, nil, 'fail')
		end)
		assert(timer.destroy(t))
		local t = timer.create(basetimeout * 2, function()
			netlink.send(pid, nil, token)
		end)
	]], basetimeout, d:getpid(), token)

	driver.setup('st', code)

	assert(tostring(driver.datareceive(d)) == token)
end)

driver.test('timer close state fail', function()
	local code = string.format([[
		local timeout = %d
		timer.create(timeout, function() end)
	]], basetimeout)

	local c = driver.setup('st', code)

	driver.failrun(c, 'could not destroy lua state', 'destroy', 'st')

	util.assertexec('sleep %q', basetimeout / 1000)
	driver.run(c, 'destroy', 'st')
end)

driver.test('timer close module fail', function()
	local code = string.format([[
		local timeout = %d
		timer.create(timeout, function() end)
	]], basetimeout)

	local c = driver.setup('st', code)

	c:close()

	local f = io.popen('sudo rmmod nflua 2>&1')
	local msg = assert(f:read())
	assert(msg == 'rmmod: ERROR: Module nflua is in use')

	util.assertexec('sleep %q', basetimeout / 1000)
	driver.reloadmodule()
end)
