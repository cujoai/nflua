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

local socket = require'socket'

local addr = assert(arg[1])
local port = assert(tonumber(arg[2]))
local timeout = assert(tonumber(arg[3]))

local server = assert(socket.bind(addr, port))
server:settimeout(timeout * 2)
local client = server:accept()
if client then
	client:settimeout(timeout)
	local msg = client:receive()
	if msg then client:send(msg .. '\n') end
	client:close()
end
server:close()
