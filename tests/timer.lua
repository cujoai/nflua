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
local data = require'data'
local socket = require'socket'

local util = require 'tests.util'

local basetimeout = 100 -- ms
local errlimit = 50 -- ms

util.test('timer create single', function()
	local c = assert(nflua.control())
	local d = assert(nflua.data())

	local code = string.format([[
		local basetimeout, pid = %d, %d
		local _, old = os.time()
		timer.create(basetimeout, function()
			local _, now = os.time()
			nf.netlink(pid, nil, tostring(now - old))
		end)
	]], basetimeout, d:getpid())

	util.run(c, 'create', 'st', 256 * 1024)
	util.run(c, 'execute', 'st', code)

	local elapsed = tonumber(tostring(util.datareceive(d))) / 1000000
	assert(elapsed >= basetimeout)
	assert(elapsed < basetimeout + errlimit)
end)

util.test('timer create multiple', function()
	local c = assert(nflua.control())
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
				nf.netlink(pid, nil, tokens[i])
			end)
		end
	]], basetimeout, d:getpid(), n, table.concat(tokens, '","'))

	util.run(c, 'create', 'st', 256 * 1024)
	util.run(c, 'execute', 'st', code)

	for i = n, 1, -1 do
		assert(tostring(util.datareceive(d)) == tokens[i])
	end
end)

util.test('timer destroy after callback', function()
	local c = assert(nflua.control())
	local d = assert(nflua.data())

	local token = util.gentoken(32)

	local code = string.format([[
		local basetimeout, pid, token = %d, %d, %q
		local t = timer.create(basetimeout, function()
			nf.netlink(pid, nil, token)
			timer.destroy(t)
		end)
	]], basetimeout, d:getpid(), token)

	util.run(c, 'create', 'st', 256 * 1024)
	util.run(c, 'execute', 'st', code)

	assert(tostring(util.datareceive(d)) == token)
end)

util.test('timer destroy before callback', function()
	local c = assert(nflua.control())
	local d = assert(nflua.data())

	local token = util.gentoken(32)

	local code = string.format([[
		local basetimeout, pid, token = %d, %d, %q
		local t = timer.create(basetimeout, function()
			nf.netlink(pid, nil, 'fail')
		end)
		timer.destroy(t)
		local t = timer.create(basetimeout * 2, function()
			nf.netlink(pid, nil, token)
		end)
	]], basetimeout, d:getpid(), token)

	util.run(c, 'create', 'st', 256 * 1024)
	util.run(c, 'execute', 'st', code)

	assert(tostring(util.datareceive(d)) == token)
end)

util.test('timer destroy state', function()
	local c = assert(nflua.control())

	util.run(c, 'create', 'st', 256 * 1024)
	util.run(c, 'execute', 'st', string.format([[
		local timeout = %d
		timer.create(timeout, function() end)
	]], basetimeout))

	util.failrun(c, 'could not destroy lua state', 'destroy', 'st')

	os.execute('sleep ' .. basetimeout / 1000)
	util.run(c, 'destroy', 'st')
end)

util.test('timer close module', function()
	local c = assert(nflua.control())

	util.run(c, 'create', 'st', 256 * 1024)
	util.run(c, 'execute', 'st', string.format([[
		local timeout = %d
		timer.create(timeout, function() end)
	]], basetimeout))

	c:close()

	local f = io.popen('sudo rmmod nflua 2>&1')
	local msg = assert(f:read())
	assert(msg == 'rmmod: ERROR: Module nflua is in use')

	os.execute('sleep ' .. basetimeout / 1000)
	assert(os.execute'sudo rmmod nflua')
	assert(os.execute'sudo insmod ./src/nflua.ko')
end)
