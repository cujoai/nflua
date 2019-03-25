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
local data = require'data'

math.randomseed(os.time())

local function gentoken(n)
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

local function datareceive(s)
	local buff = data.new(nflua.datamaxsize)
	local recv, state = assert(s:receive(buff, 0))
	return buff:segment(0, recv), state
end

local function run(s, cmd, ...)
	assert(s[cmd](s, ...) == true)
	return assert(receiveall(s))
end

local function test(name, f, ...)
	-- When nflua requires a module eg: "require('nf')" it creates
	-- a kernel module dependency, so we need to explicit destroy the states.
	local s = assert(nflua.control())
	for _, state in ipairs(run(s, 'list')) do
		run(s, 'destroy', state.name)
	end
	s:close()

	collectgarbage()

	assert(os.execute'sudo rmmod nflua')
	assert(os.execute'sudo insmod ./src/nflua.ko')

	print('testing', name)
	f(...)
end

local function matchdmesg(n, str)
	local p = assert(io.popen('dmesg | tail -' .. n), 'r')
	local out = p:read'a'
	p:close()
	if string.match(out, str) ~= str then
		error(str .. ' not found in ' .. out)
	end
end

local function kernelfail(s, msg)
	local ok, err = receiveall(s)
	assert(ok == nil)
	assert(err == 'operation could not be completed')
	matchdmesg(3, msg)
end

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
		test(t, socketclosed, socktype, cmd, defaults(socktype, cmd))
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
		test(t, doublesend, socktype, cmd, defaults(socktype, cmd))
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
	test('openclose ' .. socktype, openclose, socktype)
end

local function getfd(socktype)
	local s = assert(nflua[socktype]())

	local fd = s:getfd()
	assert(type(fd) == 'number')
end

for _, socktype in ipairs{'control', 'data'} do
	test('getfd ' .. socktype, getfd, socktype)
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
	test('getpid ' .. socktype, getpid, socktype)
end

test('control.getstate', function()
	local s = assert(nflua.control())
	assert(s:getstate() == 'ready')
end)

test('control.create', function()
	local s = assert(nflua.control())

	run(s, 'create', 'st1')
	local l = run(s, 'list')
	assert(l[1].name == 'st1')
	assert(l[1].maxalloc == nflua.defaultmaxallocbytes)
	run(s, 'destroy', 'st1')

	run(s, 'create', 'st2', 128 * 1024)
	local l = run(s, 'list')
	assert(l[1].name == 'st2')
	assert(l[1].maxalloc == 128 * 1024)

	assert(s:create('st2') == true)
	kernelfail(s, 'state already exists: st2')
	run(s, 'destroy', 'st2')

	run(s, 'create', 'st2')
	run(s, 'destroy', 'st2')

	local n = nflua.maxstates
	for i = 1, n do
		run(s, 'create', 'st' .. i)
	end
	assert(s:create('st' .. (n + 1)) == true)
	kernelfail(s, 'max states limit reached or out of memory')

	local name = string.rep('a', 64)
	local ok, err = pcall(s.create, s, name)
	assert(ok == false)
	assert(err == argerror(2, 'name too long'))
end)

test('allocation size', function()
	local s = assert(nflua.control())

	local code = 'string.rep("a", 32 * 1024)'

	run(s, 'create', 'st1')
	assert(s:execute('st1', code) == true)
	kernelfail(s, 'could not execute / load data!')

	run(s, 'create', 'st2', 128 * 1024)
	run(s, 'execute', 'st2', code)
end)

test('control.destroy', function()
	local s = assert(nflua.control())

	run(s, 'create', 'st')
	run(s, 'destroy', 'st')
	assert(#run(s, 'list') == 0)

	assert(s:destroy('st') == true)
	kernelfail(s, 'could not destroy lua state')
end)

test('control.destroy and iptables', function()
	local s = assert(nflua.control())

	run(s, 'create', 'st')
	assert(os.execute([[
		iptables -A INPUT -p 6 -m tcp --dport 63765 -m lua --state st --func t1 -j DROP
	]]))
	assert(s:destroy('st') == true)
	kernelfail(s, 'could not destroy lua state')
	assert(#run(s, 'list') == 1)

	assert(os.execute([[
		iptables -D INPUT -p 6 -m tcp --dport 63765 -m lua --state st --func t1 -j DROP
	]]))
	assert(s:destroy('st') == true)
	assert(receiveall(s) == true)
	assert(#run(s, 'list') == 0)
end)

test('control.execute', function()
	local s = assert(nflua.control())

	run(s, 'create', 'st')
	local token = gentoken()
	local code = string.format('print(%q)', token)
	run(s, 'execute', 'st', code)
	matchdmesg(4, token)

	token = gentoken()
	code = string.format('print(%q)', token)
	run(s, 'execute', 'st', code, 'test.lua')
	matchdmesg(4, token)

	run(s, 'destroy', 'st')
	assert(s:execute('st', 'print()') == true)
	kernelfail(s, 'lua state not found')

	local bigstring = gentoken(64 * 1024)
	local code = string.format('print(%q)', bigstring)
	local ok, err = s:execute('st1', code)
	assert(ok == nil)
	assert(err == 'Operation not permitted')
end)

test('control.list', function()
	local s = assert(nflua.control())

	local function statename(i)
		return string.format('st%04d', i)
	end

	local n = 10
	for i = 1, n do
		run(s, 'create', statename(i))
	end

	local l = run(s, 'list')
	assert(#l == n)
	table.sort(l, function(a, b) return a.name < b.name end)
	for i = 1, n do
		assert(l[i].name == statename(i))
	end

	for i = 1, n do
		run(s, 'destroy', statename(i))
	end

	assert(#run(s, 'list') == 0)
end)

test('control.receive', function()
	local s = assert(nflua.control())

	local ok, err = s:receive()
	assert(ok == nil)
	assert(err == 'Operation not permitted')
end)

test('data.send', function()
	local c = assert(nflua.control())
	run(c, 'create', 'st')
	run(c, 'execute', 'st', [[
		local nf = require'nf'
		function __receive_callback(pid, data)
			nf.netlink(pid, nil, data)
		end
	]])

	local s = assert(nflua.data())

	local token = gentoken()
	assert(s:send('st', data.new(token)) == true)
	local buff, state = datareceive(s)
	assert(tostring(buff) == token)
	assert(state == 'st')

	token = gentoken(nflua.datamaxsize + 1)
	local ok, err = s:send('st', data.new(token))
	assert(ok == nil)
	assert(err == 'Operation not permitted')

	local ok, err = pcall(s.send, s, 'st', 0)
	assert(ok == false)
	assert(err == argerror(3, 'expected ldata object'))
end)

test('data.receive', function()
	local c = assert(nflua.control())
	local s = assert(nflua.data())
	run(c, 'create', 'st', 256 * 1024)

	local ok, err = pcall(s.receive, s, 0, 0)
	assert(ok == false)
	assert(err == argerror(2, 'expected ldata object'))

	c:execute('st', string.format([[
		local nf = require'nf'
		nf.netlink(%d, nil, string.rep('x', 65000))
	]], s:getpid()))
	kernelfail(c, 'could not execute / load data')
end)

print'done'
