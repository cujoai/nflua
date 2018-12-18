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

local function compare(got, expected)
	if got ~= expected then
		local fmt = 'got: %s --- expected: %s'
		error(string.format(fmt, tostring(got), tostring(expected)))
	end
end

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
	local total, state
	local buff = data.new(nflua.datamaxsize)
	local offset = 0
	repeat
		local recv
		recv, total, state = assert(s:receive(buff, offset))
		offset = offset + recv
	until offset >= total
	return buff:segment(0, total), state
end

local function run(s, cmd, ...)
	compare(s[cmd](s, ...), true)
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
	assert(os.execute'sudo insmod ../src/nflua.ko')

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
	compare(ok, nil)
	compare(err, 'operation could not be completed')
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
	compare(ok, false)
	compare(err, argerror(1, 'socket closed'))
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
	compare(s[cmd](s, ...), true)
	local ok, err = s[cmd](s, ...)
	compare(ok, nil)
	compare(err, 'Operation not permitted')
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
	compare(type(s), 'userdata')
	compare(s:close(), true)

	s = assert(nflua[socktype](123))
	local ok, err = nflua[socktype](123)
	compare(ok, nil)
	compare(err, 'Address already in use')
	s:close()

	local fname = 'nflua.' .. socktype
	local ok, err = pcall(nflua[socktype], 2 ^ 31)
	compare(ok, false)
	compare(err, argerror(1, "must be in range [0, 2^31)", fname))

	local ok, err = pcall(nflua[socktype], 'a')
	compare(ok, false)
	compare(err, argerror(1, "must be integer or nil", fname))
end

for _, socktype in ipairs{'control', 'data'} do
	test('openclose ' .. socktype, openclose, socktype)
end

local function getfd(socktype)
	local s = assert(nflua[socktype]())

	local fd = s:getfd()
	compare(type(fd), 'number')
end

for _, socktype in ipairs{'control', 'data'} do
	test('getfd ' .. socktype, getfd, socktype)
end

local function getpid(socktype)
	local s = assert(nflua[socktype]())
	local pid = s:getpid()
	compare(type(pid), 'number')
	compare(pid & (2 ^ 31), 2 ^ 31)
	s:close()

	s = assert(nflua[socktype](123))
	compare(s:getpid(), 123)
end

for _, socktype in ipairs{'control', 'data'} do
	test('getpid ' .. socktype, getpid, socktype)
end

test('control.getstate', function()
	local s = assert(nflua.control())
	compare(s:getstate(), 'ready')
end)

test('control.create', function()
	local s = assert(nflua.control())

	run(s, 'create', 'st1')
	local l = run(s, 'list')
	compare(l[1].name, 'st1')
	compare(l[1].maxalloc, nflua.defaultmaxallockb)
	run(s, 'destroy', 'st1')

	run(s, 'create', 'st2', 5678)
	local l = run(s, 'list')
	compare(l[1].name, 'st2')
	compare(l[1].maxalloc, 5678)

	compare(s:create('st2'), true)
	kernelfail(s, 'state already exists: st2')
	run(s, 'destroy', 'st2')

	run(s, 'create', 'st2')
	run(s, 'destroy', 'st2')

	local n = nflua.maxstates
	for i = 1, n do
		run(s, 'create', 'st' .. i)
	end
	compare(s:create('st' .. (n + 1)), true)
	kernelfail(s, 'max states limit reached or out of memory')

	local name = string.rep('a', 64)
	local ok, err = pcall(s.create, s, name)
	compare(ok, false)
	compare(err, argerror(2, 'name too long'))
end)

test('control.destroy', function()
	local s = assert(nflua.control())

	run(s, 'create', 'st')
	run(s, 'destroy', 'st')
	compare(#run(s, 'list'), 0)

	compare(s:destroy('st'), true)
	kernelfail(s, 'could not destroy lua state')
end)

test('control.destroy and iptables', function()
	local s = assert(nflua.control())

	run(s, 'create', 'st')
	assert(os.execute([[
		iptables -A INPUT -p 6 -m tcp --dport 63765 -m lua --state st --func t1 -j DROP
	]]))
	compare(s:destroy('st'), true)
	kernelfail(s, 'could not destroy lua state')
	compare(#run(s, 'list'), 1)

	assert(os.execute([[
		iptables -D INPUT -p 6 -m tcp --dport 63765 -m lua --state st --func t1 -j DROP
	]]))
	compare(s:destroy('st'), true)
	compare(receiveall(s), true)
	compare(#run(s, 'list'), 0)
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
	compare(s:execute('st', 'print()'), true)
	kernelfail(s, 'lua state not found')

	local bigstring = gentoken(64 * 1024)
	local code = string.format('print(%q)', bigstring)
	local ok, err = s:execute('st1', code)
	compare(ok, nil)
	compare(err, 'Operation not permitted')
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
	compare(#l, n)
	table.sort(l, function(a, b) return a.name < b.name end)
	for i = 1, n do
		compare(l[i].name, statename(i))
	end

	for i = 1, n do
		run(s, 'destroy', statename(i))
	end

	compare(#run(s, 'list'), 0)
end)

test('control.receive', function()
	local s = assert(nflua.control())

	local ok, err = s:receive()
	compare(ok, nil)
	compare(err, 'Operation not permitted')
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
	compare(s:send('st', data.new(token)), true)
	local buff, state = datareceive(s)
	compare(tostring(buff), token)
	compare(state, 'st')

	token = gentoken(nflua.fragsize + 1)
	compare(s:send('st', data.new(token)), true)
	compare(tostring(datareceive(s)), token)

	token = gentoken(nflua.datamaxsize + 1)
	local ok, err = s:send('st', data.new(token))
	compare(ok, nil)
	compare(err, 'Operation not permitted')

	local ok, err = pcall(s.send, s, 'st', 0)
	compare(ok, false)
	compare(err, argerror(3, 'expected ldata object'))
end)

test('data.receive', function()
	local c = assert(nflua.control())
	local s = assert(nflua.data())
	run(c, 'create', 'st')

	local ok, err = pcall(s.receive, s, 0, 0)
	compare(ok, false)
	compare(err, argerror(2, 'expected ldata object'))

	c:execute('st', string.format([[
		local nf = require'nf'
		nf.netlink(%d, nil, string.rep('x', 65000))
	]], s:getpid()))
	kernelfail(c, 'could not execute / load data')
end)

print'done'
