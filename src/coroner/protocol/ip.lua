--- Internet protocol version 4 packet dissector.
-- This module is based on code adapted from nmap's nselib. See http://nmap.org/.
-- @classmod coroner.protocol.ip

local bit = require ("bit32")
local bstr = require ("coroner/bstr")
local ip = {}

--- IP protocol types.
-- @see ip:get_protocol
ip.proto = {
	IPPROTO_HOPOPT = 0x00,      -- IPv6 Hop-by-Hop Option
	IPPROTO_ICMP = 0x01,        -- Internet Control Message Protocol
	IPPROTO_IGMP = 0x02,        -- Internet Group Management Protocol
	IPPROTO_IPIP = 0x04,        -- IP in IP (encapsulation)
	IPPROTO_TCP = 0x06,         -- Transmission Control Protocol
	IPPROTO_EGP = 0x08,         -- Exterior Gateway Protocol
	IPPROTO_UDP = 0x11,         -- User Datagram Protocol
	IPPROTO_IPV6 = 0x29,        -- IPv6 Encapsulation
	IPPROTO_IPV6ROUTE = 0x2B,   -- Routing Header for IPv6
	IPPROTO_IPV6FRAG = 0x2C,    -- Fragment Header for IPv6
	IPPROTO_IPV6ICMP = 0x3A,    -- ICMP for IPv6
	IPPROTO_IPV6NONXT = 0x3B,   -- No Next Header for IPv6
	IPPROTO_IPV6DSTOPTS = 0x3C, -- Destination Options for IPv6
	IPPROTO_IPV6MOBHDR = 0x87   -- Mobility Extension Header for IPv6
}

local function raw (buff, index, length)
	if not index then index = 0 end
	if not length then length = #buff - index end

	return string.char(string.byte(buff, index+1, index+1+length-1))
end

local function ip_ntop (buff)
	return ("%d.%d.%d.%d"):format (buff:byte (1),
									buff:byte (2),
									buff:byte (3),
									buff:byte (4))
end

local function ip_parseopts (buff, offset, length)
	local options = {}
	local op = 1
	local opt_ptr = 0

	while opt_ptr < length do
		local t, l, d
		options[op] = {}

		t = bstr.u8(buff, offset + opt_ptr)
		options[op].type = t

		if t==0 or t==1 then
			l = 1
			d = nil
		else
			l = bstr.u8(buff, offset + opt_ptr + 1)

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

--- Create a new object.
-- @tparam string packet pass packet data as an opaque string
-- @treturn table New ip table.
function ip:new (packet)
	if type (packet) ~= "string" then
		error ("parameter 'packet' is not a string", 2)
	end

	local ip_pkt = setmetatable ({}, { __index = ip })

	ip_pkt.buff = packet

	return ip_pkt
end

--- Parse the packet data.
-- @treturn boolean True on success, false on failure (error message is set).
-- @see ip:new
-- @see ip:set_packet
function ip:parse ()
	if self.buff == nil then
		self.errmsg = "no data"
		return false
	elseif string.len (self.buff) < 20 then
		self.errmsg = "incomplete IP header data"
		return false
	end

	self.ip_v = bit.rshift (bit.band (bstr.u8 (self.buff, 0), 0xF0), 4)
	self.ip_hl = bit.band (bstr.u8 (self.buff, 0), 0x0F) * 4

	if self.ip_v ~= 4 then
		self.errmsg = "not an IP packet"
		return false
	end

	self.ip_tos = bstr.u8 (self.buff, 1)
	self.ip_len = bstr.u16 (self.buff, 2)
	self.ip_id = bstr.u16 (self.buff, 4)
	self.ip_off = bstr.u16 (self.buff, 6)
	self.ip_rf = bit.band (self.ip_off, 0x8000) ~= 0
	self.ip_df = bit.band (self.ip_off, 0x4000) ~= 0
	self.ip_mf = bit.band (self.ip_off, 0x2000) ~= 0
	self.ip_off = bit.band (self.ip_off, 0x1FFF)
	self.ip_ttl = bstr.u8 (self.buff, 8)
	self.ip_proto = bstr.u8 (self.buff, 9)
	self.ip_sum = bstr.u16 (self.buff, 10)
	self.ip_src = raw (self.buff, 12, 4)
	self.ip_dst = raw (self.buff, 16, 4)
	self.ip_opt_offset = 20
	self.ip_options = ip_parseopts (self.buff, self.ip_opt_offset, (self.ip_hl - 20))

	return true
end

--- Get the module name.
-- @treturn string Module name.
function ip:type ()
	return "ip"
end

--- Get raw packet data uncapsulated in the IP packet data.
-- @treturn string Raw packet data or an empty string.
function ip:get_rawpacket ()
	if string.len (self.buff) > 20 then
		return string.sub (self.buff, self.ip_hl + 1, -1)
	end

	return ""
end

--- Change or set new packet data.
-- @tparam string packet byte string of packet data
function ip:set_packet (packet)
	if type (packet) ~= "string" then
		error ("parameter 'packet' is not a string", 2)
	end

	self.buff = packet
end

--- Get packet's IP address version.
-- @treturn integer IP address version.
function ip:get_version ()
	return 4
end

--- Get packet's source IP address.
-- @treturn string IP address formatted as XXX.XXX.XXX.XXX string.
function ip:get_saddr ()
	return ip_ntop (self.ip_src)
end

--- Get packet's source IP address.
-- @treturn string Byte string representing an IP address.
function ip:get_rawsaddr ()
	return self.ip_src
end

--- Get packet's destination IP address.
-- @treturn string IP address formatted as XXX.XXX.XXX.XXX string.
function ip:get_daddr ()
	return ip_ntop (self.ip_dst)
end

--- Get packet's destination IP address.
-- @treturn string Byte string representing an IP address.
function ip:get_rawdaddr ()
	return self.ip_dst
end

--- Get packet's ID.
-- @treturn integer Packet ID.
function ip:get_id ()
	return self.ip_id
end

--- Get packet's TTL value.
-- @treturn integer Packet TTL value.
function ip:get_ttl ()
	return self.ip_ttl
end

--- Get packet's protocol ID.
-- @treturn integer A value representing a type of encapsulated data.
-- @see ip.proto
function ip:get_protocol ()
	return self.ip_proto
end

--- Get packet's length.
-- @treturn integer Packet length.
function ip:get_length ()
	return self.ip_len
end

--- Get packet's header length.
-- @treturn integer Header length.
function ip:get_hdrlen ()
	return self.ip_hl
end

--- Get packet's header checksum.
-- @treturn integer Header checksum.
function ip:get_hdrchecksum ()
	return self.ip_sum
end

--- Get packet's fragment offset.
-- @treturn integer Fragment offset.
function ip:get_fragoffset ()
	return self.ip_off
end

--- Get last error message.
-- @treturn string Error message.
function ip:get_error ()
	return self.errmsg or "no error"
end

return ip

