--[[
--
-- Parse IP header and return extracted information in a table.
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

local ip = {}

function ip.parse (buffer, pos)
	local tmp_ip = {
		IPPROTO_ICMP = 0x01,
		IPPROTO_TCP = 0x06,
		IPPROTO_UDP = 0x11
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

	tmp_ip.version = ((buffer:byte (buff_pos) & 0xF0) >> 4)
	tmp_ip.hdr_len = ((buffer:byte (buff_pos) & 0x0F) << 2)

	buff_pos = buff_pos + 1

	-- Skip 'differentiated services' byte
	buff_pos = buff_pos + 1

	tmp_ip.tot_len = (buffer:byte (buff_pos) << 8) | (buffer:byte (buff_pos + 1) & 0xFF)

	buff_pos = buff_pos + 2

	tmp_ip.id = (buffer:byte (buff_pos) << 8) | (buffer:byte (buff_pos + 1) & 0xFF)

	buff_pos = buff_pos + 2

	tmp_ip.flags = buffer:byte (buff_pos)

	-- Do not increment the pos, fragment pos begins at the same byte
	--buff_pos = buff_pos + 1

	tmp_ip.frag_off = (buffer:byte (buff_pos) << 8) | (buffer:byte (buff_pos + 1) & 0xFF)

	buff_pos = buff_pos + 2

	tmp_ip.ttl = buffer:byte (buff_pos)

	buff_pos = buff_pos + 1

	tmp_ip.proto = buffer:byte (buff_pos)

	buff_pos = buff_pos + 1

	tmp_ip.checksum = (buffer:byte (buff_pos) << 8) | (buffer:byte (buff_pos + 1) & 0xFF)

	buff_pos = buff_pos + 2

	tmp_ip.src = string.format ("%d.%d.%d.%d",
									buffer:byte (buff_pos),
									buffer:byte (buff_pos + 1),
									buffer:byte (buff_pos + 2),
									buffer:byte (buff_pos + 3))

	buff_pos = buff_pos + 4

	tmp_ip.dst = string.format ("%d.%d.%d.%d",
									buffer:byte (buff_pos),
									buffer:byte (buff_pos + 1),
									buffer:byte (buff_pos + 2),
									buffer:byte (buff_pos + 3))

	buff_pos = buff_pos + 4

	return tmp_ip, buff_pos
end

return ip

