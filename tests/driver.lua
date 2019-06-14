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

local network = require'tests.network'
local util = require'tests.util'

local driver = {}

local rmmodule = 'sudo rmmod nflua'
local loadmodule = 'sudo insmod ./src/nflua.ko'

function driver.reloadmodule()
	util.assertexec(rmmodule)
	util.assertexec(loadmodule)
end

network.cleanup()
util.silentexec(rmmodule)
util.silentexec(loadmodule)

local function receiveall(s)
	local ret
	repeat ret = {s:receive()} until ret[2] ~= 'pending'
	return table.unpack(ret)
end

function driver.datareceive(s)
	local buff = memory.create(nflua.datamaxsize)
	local recv, state = assert(s:receive(buff, 0))
	return memory.tostring(buff, 1, recv), state
end

function driver.run(s, cmd, ...)
	assert(s[cmd](s, ...))
	return assert(receiveall(s))
end

function driver.test(name, f, ...)
	print('testing', name)
	network.setup()
	f(...)
	collectgarbage()
	network.cleanup()
	driver.reloadmodule()
end

function driver.matchdmesg(n, str)
	local _, out = assert(util.pipeexec('dmesg | tail -%d', n))
	assert(string.find(out, str))
end

function driver.failrun(s, msg, cmd, ...)
	assert(s[cmd](s, ...))
	local ok, err = receiveall(s)
	assert(ok == nil)
	assert(err == 'operation could not be completed')
	driver.matchdmesg(3, msg)
end

function driver.setup(st, code, loadutil)
	local c = assert(nflua.control())
	driver.run(c, 'create', st, 1024 ^ 3)
	if code then
		driver.run(c, 'execute', st, code)
	end
	if loadutil then
		local path = package.searchpath('tests.nfutil', package.path)
		local f = io.open(path)
		driver.run(c, 'execute', st, f:read'a')
		f:close()
	end
	return c
end

return driver
