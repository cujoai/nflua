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
local memory = require'memory'
local fcntl = require'posix.fcntl'
local poll = require'posix.poll'
local driver = require'tests.driver'
local util = require'tests.util'

local nthreads = 10
local timeout = 10 -- ms

local function run(loop)
	while next(loop) do
		local ok, err = poll.poll(loop, timeout)
		assert(ok and ok > 0, err)
		for fd in pairs(loop) do
			for ev, ready in pairs(loop[fd].revents) do
				if ready and loop[fd] then
					assert(coroutine.resume(
						loop[fd].thread, ev))
				end
			end
		end
	end
end

local function execute(loop, sock, cmd, ...)
	local fd = sock:getfd()
	loop[fd] = {thread = coroutine.running()}
	local ret, err

	loop[fd].events = {OUT = true}
	repeat
		assert(coroutine.yield() == 'OUT')
		ret, err = sock[cmd](sock, ...)
	until ret or err ~= 'pending'
	if not ret then goto out end

	loop[fd].events = {IN = true}
	repeat
		assert(coroutine.yield() == 'IN')
		ret, err = sock:receive()
	until ret or err ~= 'pending'

	::out::
	loop[fd] = nil
	return ret, err
end

local function spawn(f)
	local sock = assert(nflua.control())
	fcntl.fcntl(sock:getfd(), fcntl.O_NONBLOCK, 1)
	assert(coroutine.resume(coroutine.create(f), sock))
end

driver.test('nonblock big send', function()
	local loop = {}
	for i = 1, nthreads do
		spawn(function(sock)
			local st = 'st' .. i
			assert(execute(loop, sock, 'create', st))
			local token = util.gentoken()
			local code = string.format('-- %s\nprint(%q)',
				string.rep('a', 50 * 1024), token)
			assert(execute(loop, sock, 'execute', st, code))
			driver.matchdmesg(2 * nthreads, token)
		end)
	end
	run(loop)
end)

driver.test('nonblock big receive', function()
	local loop = {}
	spawn(function(sock)
		for i = 1, nflua.maxstates do
			assert(execute(loop, sock, 'create', 'st' .. i))
		end
	end)
	run(loop)
	for i = 1, nthreads do
		spawn(function(sock)
			local sts = assert(execute(loop, sock, 'list'))
			assert(#sts == nflua.maxstates)
		end)
	end
	run(loop)
end)
