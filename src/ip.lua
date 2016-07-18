local bit = require ("bit32")
local stdint = require ("stdint")
local ip = {}

-- TODO
local function raw (buff, index, length)
	if not index then index = 0 end
	if not length then length = #buff - index end

	return string.char(string.byte(buff, index+1, index+1+length-1))
end

local function ip_ntop ()
	return ("%d.%d.%d.%d"):format (buffer:byte (buff_pos),
									buffer:byte (buff_pos + 1),
									buffer:byte (buff_pos + 2),
									buffer:byte (buff_pos + 3))
end

local function ip_parseopts (buff, offset, length)
	local options = {}
	local op = 1
	local opt_ptr = 0

	while opt_ptr < length do
		local t, l, d
		options[op] = {}

		t = stdint.u8(buff, offset + opt_ptr)
		options[op].type = t

		if t==0 or t==1 then
			l = 1
			d = nil
		else
			l = stdint.u8(buff, offset + opt_ptr + 1)

			if l > 2 then
				d = raw(buff, offset + opt_ptr + 2, l-2)
			end
		end

		options[op].len  = l
		options[op].data = d
		opt_ptr = opt_ptr + l
		op = op + 1
	end

	return options
end

function ip.new (packet)
	if type (packet) ~= "string" then
		error ("parameter 'frame' is not a string", 2)
	end

	local ip_pkt = setmetatable ({}, { __index = ip })

	ip_pkt.buff = packet

	return ip_pkt
end

function ip:parse ()
	if string.len (self.buff) < 20 then
		self.errmsg = "incomplete IP header data"
		return false
	end

	self.ip_offset = 0

	self.ip_v = bit.rshift (bit.band (stdint.u8 (self.buff, self.ip_offset + 0), 0xF0), 4)
	self.ip_hl = bit.band (stdint.u8 (self.buff, self.ip_offset + 0), 0x0F) -- header_length or data_offset

	if self.ip_v ~= 4 then
		self.errmsg = "not an IPv4 packet"
		return false
	end

	self.ip_tos = stdint.u8 (self.buff, self.ip_offset + 1)
	self.ip_len = stdint.u16 (self.buff, self.ip_offset + 2)
	self.ip_id = stdint.u16 (self.buff, self.ip_offset + 4)
	self.ip_off = stdint.u16 (self.buff, self.ip_offset + 6)
	self.ip_rf = bit.band (self.ip_off, 0x8000) ~= 0 -- true/false
	self.ip_df = bit.band (self.ip_off, 0x4000) ~= 0
	self.ip_mf = bit.band (self.ip_off, 0x2000) ~= 0
	self.ip_off = bit.band (self.ip_off, 0x1FFF) -- fragment offset
	self.ip_ttl = stdint.u8 (self.buff, self.ip_offset + 8)
	self.ip_p = stdint.u8 (self.buff, self.ip_offset + 9)
	self.ip_sum = stdint.u16 (self.buff, self.ip_offset + 10)
	self.ip_src = raw (self.buff, self.ip_offset + 12, 4) -- raw 4-bytes string
	self.ip_dst = raw (self.buff, self.ip_offset + 16, 4)
	self.ip_opt_offset = self.ip_offset + 20
	self.ip_options = ip_parseopts (self.buff, self.ip_opt_offset, ((self.ip_hl * 4) - 20))
	self.ip_data_offset = self.ip_offset + self.ip_hl * 4

	return true
end

-- TODO
function ip:get_rawpacket ()
	return ""
end

function ip:set_packet (packet)
	self.buff = packet
end

function ip:get_saddr ()
	return ip_ntop (self.ip_src)
end

function ip:get_daddr ()
	return ip_ntop (self.ip_dst)
end

function ip:get_rawsaddr ()
	return self.ip_src
end

function ip:get_rawdaddr ()
	return self.ip_dst
end

function ip:get_error ()
	return self.errmsg
end

return ip

