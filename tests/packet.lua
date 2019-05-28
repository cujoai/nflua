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

local driver = require'tests.driver'
local network = require'tests.network'
local util = require'tests.util'

driver.test('packet tcpreply', function ()
	local token = util.gentoken()
	local code = string.format([[
		function f()
			nf.reply('tcp', %q .. '\n')
			return false
		end
	]], token)
	driver.setup('st', code)
	util.assertexec('iptables -A ' .. network.toserver ..
		' -m lua --tcp-payload --state st --function f')
	network.asserttraffic(token)
end)
