--[[
--
-- Parse Ethernet II header and return extracted information in a table.
--
-- Copyright (c) 2016, Dan Antagon <antagon@codeward.org>
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy of
-- this software and associated documentation files (the "Software"), to deal in
-- the Software without restriction, including without limitation the rights to
-- use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
-- of the Software, and to permit persons to whom the Software is furnished to do
-- so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--]]

local eth = {}

function eth.parse (buffer, pos)
	local tmp_eth = {
		PROTO_IP = 0x0800,
		PROTO_ARP = 0x0806,
		PROTO_IP6 = 0x86DD
	}
	local buff_pos = nil

	if type (buffer) ~= "string" then
		error ("parameter 'buffer' is not a string (got " .. type (buffer) .. ")", 2)
	end

	if type (pos) ~= "number" and type (pos) ~= "nil" then
		error ("parameter 'pos' is not a number (got " .. type (pos) .. ")", 2)
	end

	if pos then
		buff_pos = pos
	else
		buff_pos = 1
	end

	tmp_eth.dst = string.format ("%02x:%02x:%02x:%02x:%02x:%02x",
									buffer:byte (buff_pos),
									buffer:byte (buff_pos + 1),
									buffer:byte (buff_pos + 2),
									buffer:byte (buff_pos + 3),
									buffer:byte (buff_pos + 4),
									buffer:byte (buff_pos + 5))

	buff_pos = buff_pos + 6

	tmp_eth.src = string.format ("%02x:%02x:%02x:%02x:%02x:%02x",
									buffer:byte (buff_pos),
									buffer:byte (buff_pos + 1),
									buffer:byte (buff_pos + 2),
									buffer:byte (buff_pos + 3),
									buffer:byte (buff_pos + 4),
									buffer:byte (buff_pos + 5))

	buff_pos = buff_pos + 6

	tmp_eth.proto = (buffer:byte (buff_pos) << 8) | (buffer:byte (buff_pos + 1) & 0xFF)

	buff_pos = buff_pos + 2

	return tmp_eth, buff_pos
end

return eth

