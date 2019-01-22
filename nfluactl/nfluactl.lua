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

local usage = string.format([[
usage: lua %s <command> [<args>]
Available commands:
  create <state> [maxalloc]
  destroy <state>
  list
  execute <state> (<file> | -e <expression>)
  send <state> [pid]
  receive <pid>]], arg[0])

local function abort(err)
	io.stderr:write('error: ', tostring(err), '\n')
	os.exit(1)
end

local function check(ok, ...)
	if not ok then abort(...) end
	return ok, ...
end

local function ccall(...)
	return check(select(2, check(pcall(...))))
end

local function run(cmd, ...)
	local s = nflua.control()
	ccall(s[cmd], s, ...)
	local r, err
	repeat r, err = s:receive() until err ~= 'pending'
	check(r, err)
	s:close()
	return r
end

if arg[1] == '-h' or arg[1] == '--help' then
	print(usage)
elseif arg[1] == 'create' then
	run('create', table.unpack(arg, 2, 3))
elseif arg[1] == 'destroy' then
	run('destroy', table.unpack(arg, 2, 2))
elseif arg[1] == 'list' then
	local states = run('list')
	print'name\t\tmaxalloc\tcurralloc'
	for _, state in ipairs(states) do
		print(string.format('%-16s%-16d%-16d', state.name,
			state.maxalloc, state.curralloc))
	end
elseif arg[1] == 'execute' then
	local code
	if arg[3] == '-e' then
		code = arg[4]
	else
		local f = check(io.open(arg[3], 'r'))
		code = check(f:read'a')
		f:close()
	end
	run('execute', arg[2], code)
elseif arg[1] == 'send' then
	local s = ccall(nflua.data, tonumber(arg[3]))
	local state = arg[2]
	local buffer = data.new(io.read'a')
	ccall(s.send, s, state, buffer)
	s:close()
elseif arg[1] == 'receive' then
	local pid = check(arg[2], 'missing pid')
	local s = ccall(nflua.data, tonumber(pid))
	while true do print(tostring(ccall(s.receive, s))) end
else
	abort('unknown option ' .. tostring(arg[1]) .. '\n' .. usage)
end
