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

local driver = require'tests.driver'
local network = require'tests.network'
local util = require'tests.util'

local function argerror(arg, msg, fname)
	fname = fname or '?'
	return string.format("bad argument #%d to '%s' (%s)", arg, fname, msg)
end

local function defaults(socktype, cmd)
	if socktype == 'control' then
		if cmd == 'create' then
			return 'st'
		elseif cmd == 'destroy' then
			return 'st'
		elseif cmd == 'execute' then
			return 'st', 'print()'
		end
	else
		if cmd == 'send' then
			return 'st', 'b'
		end
	end
end

local function socketclosed(socktype, cmd, ...)
	local s = assert(nflua[socktype]())
	s:close()
	local ok, err = pcall(s[cmd], s, ...)
	assert(ok == false)
	assert(err == argerror(1, 'socket closed'))
end

local cases = {
	control = {'close', 'getfd', 'getpid', 'getstate', 'create', 'destroy',
			   'execute', 'list', 'receive'},
	data = {'close', 'getfd', 'getpid', 'send', 'receive'},
}

for socktype, cmds in pairs(cases) do
	for _, cmd in ipairs(cmds) do
		local t = 'socketclosed ' .. socktype .. ' ' .. cmd
		driver.test(t, socketclosed, socktype, cmd, defaults(socktype, cmd))
	end
end

local function doublesend(socktype, cmd, ...)
	local s = assert(nflua[socktype]())
	assert(s[cmd](s, ...) == true)
	local ok, err = s[cmd](s, ...)
	assert(ok == nil)
	assert(err == 'Operation not permitted')
end

local cases = {
	control = {'create', 'destroy', 'execute', 'list'},
}

for socktype, cmds in pairs(cases) do
	for _, cmd in ipairs(cmds) do
		local t = 'doublesend ' .. socktype .. ' ' .. cmd
		driver.test(t, doublesend, socktype, cmd, defaults(socktype, cmd))
	end
end

local function openclose(socktype)
	local s = assert(nflua[socktype]())
	assert(type(s) == 'userdata')
	assert(s:close() == true)

	s = assert(nflua[socktype](123))
	local ok, err = nflua[socktype](123)
	assert(ok == nil)
	assert(err == 'Address already in use')
	s:close()

	local fname = 'nflua.' .. socktype
	local ok, err = pcall(nflua[socktype], 2 ^ 31)
	assert(ok == false)
	assert(err == argerror(1, "must be in range [0, 2^31)", fname))

	local ok, err = pcall(nflua[socktype], 'a')
	assert(ok == false)
	assert(err, argerror(1, "must be integer or nil" == fname))
end

for _, socktype in ipairs{'control', 'data'} do
	driver.test('openclose ' .. socktype, openclose, socktype)
end

local function getfd(socktype)
	local s = assert(nflua[socktype]())

	local fd = s:getfd()
	assert(type(fd) == 'number')
end

for _, socktype in ipairs{'control', 'data'} do
	driver.test('getfd ' .. socktype, getfd, socktype)
end

local function getpid(socktype)
	local s = assert(nflua[socktype]())
	local pid = s:getpid()
	assert(type(pid) == 'number')
	assert(pid & (2 ^ 31) == 2 ^ 31)
	s:close()

	s = assert(nflua[socktype](123))
	assert(s:getpid() == 123)
end

for _, socktype in ipairs{'control', 'data'} do
	driver.test('getpid ' .. socktype, getpid, socktype)
end

driver.test('control.getstate', function()
	local s = assert(nflua.control())
	assert(s:getstate() == 'ready')
end)

driver.test('control.create', function()
	local s = assert(nflua.control())

	driver.run(s, 'create', 'st1')
	local l = driver.run(s, 'list')
	assert(l[1].name == 'st1')
	assert(l[1].maxalloc == nflua.defaultmaxallocbytes)
	driver.run(s, 'destroy', 'st1')

	driver.run(s, 'create', 'st2', 128 * 1024)
	local l = driver.run(s, 'list')
	assert(l[1].name == 'st2')
	assert(l[1].maxalloc == 128 * 1024)

	driver.failrun(s, 'state already exists: st2', 'create', 'st2')
	driver.run(s, 'destroy', 'st2')

	driver.run(s, 'create', 'st2')
	driver.run(s, 'destroy', 'st2')

	local n = nflua.maxstates
	for i = 1, n do
		driver.run(s, 'create', 'st' .. i)
	end
	driver.failrun(s, 'max states limit reached or out of memory',
		'create', 'st' .. (n + 1))

	local name = string.rep('a', 64)
	local ok, err = pcall(s.create, s, name)
	assert(ok == false)
	assert(err == argerror(2, 'name too long'))
end)

driver.test('allocation size', function()
	local s = assert(nflua.control())

	local code = 'string.rep("a", 32 * 1024)'

	driver.run(s, 'create', 'st1')
	driver.failrun(s, 'could not execute / load data!',
		'execute', 'st1', code)

	driver.run(s, 'create', 'st2', 128 * 1024)
	driver.run(s, 'execute', 'st2', code)
end)

driver.test('control.destroy', function()
	local s = assert(nflua.control())

	driver.run(s, 'create', 'st')
	driver.run(s, 'destroy', 'st')
	assert(#driver.run(s, 'list') == 0)

	driver.failrun(s, 'could not destroy lua state', 'destroy', 'st')
end)

driver.test('control.destroy and iptables', function()
	local s = assert(nflua.control())

	local rule = network.toserver .. ' -m lua --state st --function f'

	driver.run(s, 'create', 'st')
	util.assertexec('iptables -A %s', rule)
	driver.failrun(s, 'could not destroy lua state', 'destroy', 'st')
	assert(#driver.run(s, 'list') == 1)

	util.assertexec('iptables -D %s', rule)
	driver.run(s, 'destroy', 'st')
	assert(#driver.run(s, 'list') == 0)
end)

driver.test('control.execute', function()
	local s = assert(nflua.control())

	driver.run(s, 'create', 'st')
	local token = util.gentoken()
	local code = string.format('print(%q)', token)
	driver.run(s, 'execute', 'st', code)
	driver.matchdmesg(4, token)

	token = util.gentoken()
	code = string.format('print(%q)', token)
	driver.run(s, 'execute', 'st', code, 'test.lua')
	driver.matchdmesg(4, token)

	driver.run(s, 'destroy', 'st')
	driver.failrun(s, 'lua state not found', 'execute', 'st', 'print()')

	local bigstring = util.gentoken(64 * 1024)
	local code = string.format('print(%q)', bigstring)
	local ok, err = s:execute('st1', code)
	assert(ok == nil)
	assert(err == 'Operation not permitted')
end)

driver.test('control.list', function()
	local s = assert(nflua.control())

	local function statename(i)
		return string.format('st%04d', i)
	end

	local n = 10
	for i = 1, n do
		driver.run(s, 'create', statename(i))
	end

	local l = driver.run(s, 'list')
	assert(#l == n)
	table.sort(l, function(a, b) return a.name < b.name end)
	for i = 1, n do
		assert(l[i].name == statename(i))
	end

	for i = 1, n do
		driver.run(s, 'destroy', statename(i))
	end

	assert(#driver.run(s, 'list') == 0)
end)

driver.test('control.receive', function()
	local s = assert(nflua.control())

	local ok, err = s:receive()
	assert(ok == nil)
	assert(err == 'Operation not permitted')
end)

driver.test('data.send', function()
	local c = assert(nflua.control())
	driver.run(c, 'create', 'st')
	driver.run(c, 'execute', 'st', [[
		function __receive_callback(pid, data)
			nf.netlink(pid, nil, data)
		end
	]])

	local s = assert(nflua.data())

	local token = util.gentoken()
	assert(s:send('st', data.new(token)) == true)
	local buff, state = driver.datareceive(s)
	assert(tostring(buff) == token)
	assert(state == 'st')

	token = util.gentoken(nflua.datamaxsize + 1)
	local ok, err = s:send('st', data.new(token))
	assert(ok == nil)
	assert(err == 'Operation not permitted')

	local ok, err = pcall(s.send, s, 'st', 0)
	assert(ok == false)
	assert(err == argerror(3, 'expected ldata object'))
end)

driver.test('data.receive', function()
	local c = assert(nflua.control())
	local s = assert(nflua.data())
	driver.run(c, 'create', 'st', 256 * 1024)

	local ok, err = pcall(s.receive, s, 0, 0)
	assert(ok == false)
	assert(err == argerror(2, 'expected ldata object'))

	local code = string.format([[
		nf.netlink(%d, nil, string.rep('x', 65000))
	]], s:getpid())
	driver.failrun(c, 'could not execute / load data', 'execute', 'st', code)
end)
