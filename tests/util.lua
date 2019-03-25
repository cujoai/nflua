--
-- Copyright (C) 2019 CUJO LLC
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
--

local nflua = require'nflua'

local util = {}

math.randomseed(os.time())

function util.gentoken(n)
	n = n or 16
	local s = {}
	for i = 1, n do
		s[i] = math.random(0, 9)
	end
	return table.concat(s)
end

local function receiveall(s)
	local ret
	repeat ret = {s:receive()} until ret[2] ~= 'pending'
	return table.unpack(ret)
end

function util.run(s, cmd, ...)
	assert(s[cmd](s, ...) == true)
	return assert(receiveall(s))
end

function util.test(name, f, ...)
	-- When nflua requires a module eg: "require('nf')" it creates
	-- a kernel module dependency, so we need to explicit destroy the states.
	local s = assert(nflua.control())
	for _, state in ipairs(util.run(s, 'list')) do
		util.run(s, 'destroy', state.name)
	end
	s:close()

	collectgarbage()

	assert(os.execute'sudo rmmod nflua')
	assert(os.execute'sudo insmod ./src/nflua.ko')

	print('testing', name)
	f(...)
end

function util.matchdmesg(n, str)
	local p = assert(io.popen('dmesg | tail -' .. n), 'r')
	local out = p:read'a'
	p:close()
	if string.match(out, str) ~= str then
		error(str .. ' not found in ' .. out)
	end
end

function util.failrun(s, msg, cmd, ...)
	assert(s[cmd](s, ...) == true)
	local ok, err = receiveall(s)
	assert(ok == nil)
	assert(err == 'operation could not be completed')
	util.matchdmesg(3, msg)
end

return util
