--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
local socket = require'socket.core'

local KERNEL_PORT = 0
local NETLINK_NFLUA = 31

function nfdofile(path)
	assert(path ~= nil, 'path argument is mandatory')

	local file = assert(io.open(path))
	local code = assert(file:read('a'))
	file:close()

	assert(socket.netlink(NETLINK_NFLUA):sendto(path .. '\0' .. code, KERNEL_PORT))
end

function printusage()
	local lines = {
		"usage: lua nfluaclt.lua [options] [script [args]]",
		"Available options are:",
		"  -e stat  execute string 'stat'",
		"  -h       print this message",
		"  --       stop handling options",
	}
	print(table.concat(lines, '\n'))
end

local options = {
	['-e'] = function(code)
		assert(code ~= nil, 'code argument is mandatory')
		assert(socket.netlink(NETLINK_NFLUA):sendto(code, KERNEL_PORT))
		return 1
	end,
	['-h'] = function()
		printusage()
		os.exit(0)
		return 0
	end,
}

function handleoptions(...)
	local i = 1
	while select(i, ...) ~= nil do
		local option = select(i, ...)
		if option == '--' then
			i = i + 1
			break
		end
		if not (option:sub(1,1) == '-') then break end

		local handler = options[option]
		if handler == nil then
			print(arg[0] .. string.format(": unrecognized option '%s'", option))
			printusage()
			os.exit(1)
		end
		local shiftcount = handler(select(i + 1, ...))
		i = i + 1 + shiftcount
	end
	return i
end

local argindex = handleoptions(...)
if select(argindex, ...) ~= nil then nfdofile(select(argindex, ...)) end
