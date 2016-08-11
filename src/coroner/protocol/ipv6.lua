--- Internet protocol version 6 packet dissector.
-- Please note, that extension headers are skipped over automatically, call to
-- **ipv6:get_nexthdrtype** returns the first non extension header type.
--
-- This module is based on code adapted from nmap's nselib. See http://nmap.org/.
-- @classmod coroner.protocol.ipv6
local bit = require ("bit32")
local bstr = require ("coroner/bstr")
local ipv6 = {}

--- IPv6 protocol types.
-- @see ipv6:get_nexthdrtype
ipv6.proto = {
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
	return ("%x:%x:%x:%x:%x:%x:%x:%x"):format (
		bstr.u16 (buff, 0), bstr.u16 (buff, 2), bstr.u16 (buff, 4),
		bstr.u16 (buff, 6), bstr.u16 (buff, 8), bstr.u16 (buff, 10),
		bstr.u16 (buff, 12), bstr.u16 (buff, 14))
end

local function is_extensionhdr (nhdr)
	return nhdr == ipv6.proto.IPPROTO_HOPOPT
			or nhdr == ipv6.proto.IPPROTO_IPV6ROUTE
			or nhdr == ipv6.proto.IPPROTO_IPV6FRAG
			or nhdr == ipv6.proto.IPPROTO_IPV6DSTOPTS
end

--- Create a new object.
-- @tparam string packet pass packet data as an opaque string
-- @treturn table New ipv6 table.
function ipv6:new (packet)
	if type (packet) ~= "string" then
		error ("parameter 'packet' is not a string", 2)
	end

	local ipv6_pkt = setmetatable ({}, { __index = ipv6 })

	ipv6_pkt.buff = packet

	return ipv6_pkt
end

--- Parse the packet data.
-- @treturn boolean True on success, false on failure (error message is set).
-- @see ipv6:new
-- @see ipv6:set_packet
function ipv6:parse ()
	if self.buff == nil then
		self.errmsg = "no data"
		return false
	elseif string.len (self.buff) < 40 then
		self.errmsg = "incomplete IPv6 header data"
		return false
	end

	self.ip_v = bit.rshift (bit.band (bstr.u8 (self.buff, 0), 0xF0), 4)

	if self.ip_v ~= 6 then
		self.errmsg = "not an IPv6 packet"
		return false
	end

	self.ip6_tc = bit.rshift (bit.band (bstr.u16 (self.buff, 0), 0x0FF0), 4)
	self.ip6_fl = bit.band (bstr.u8 (self.buff, 1), 0x0F) * 65536 + bstr.u16 (self.buff, 2)
	self.ip6_plen = bstr.u16 (self.buff, 4)
	self.ip6_nhdr = bstr.u8 (self.buff, 6)
	self.ip6_hlimt = bstr.u8 (self.buff, 7)
	self.ip6_src = raw (self.buff, 8, 16)
	self.ip6_dst = raw (self.buff, 24, 16)
	self.ip6_poff = 40 -- Payload offset

	while is_extensionhdr (self.ip6_nhdr) do
		self.ip6_nhdr = bstr.u8 (self.buff, self.ip6_poff)
		self.ip6_poff = self.ip6_poff + (bstr.u8 (self.buff, self.ip6_poff + 1) * 8) + 8
	end

	return true
end

--- Get the module name.
-- @treturn string Module name.
function ipv6:type ()
	return "ipv6"
end

--- Get raw packet data uncapsulated in the IPv6 packet data. This method skips
-- all extension headers.
-- @treturn string Raw packet data or an empty string.
function ipv6:get_rawpacket ()
	if string.len (self.buff) > 40 then
		return string.sub (self.buff, self.ip6_poff + 1, -1)
	end

	return ""
end

--- Change or set new packet data.
-- @tparam string packet byte string of packet data
function ipv6:set_packet (packet)
	self.buff = packet
end

--- Get packet's IP address version.
-- @treturn integer IP address version.
function ipv6:get_version ()
	return 6
end

--- Get packet's source IP address.
-- @treturn string IP address formatted as XXX.XXX.XXX.XXX string.
function ipv6:get_saddr ()
	return ip_ntop (self.ip6_src)
end

--- Get packet's source IP address.
-- @treturn string Byte string representing an IP address.
function ipv6:get_rawsaddr ()
	return self.ip6_src
end

--- Get packet's destination IP address.
-- @treturn string IPv6 address formatted as XXX.XXX.XXX.XXX string.
function ipv6:get_daddr ()
	return ip_ntop (self.ip6_dst)
end

--- Get packet's destination IP address.
-- @treturn string Byte string representing an IP address.
function ipv6:get_rawdaddr ()
	return self.ip6_dst
end

--- Get packet's traffic class.
-- @treturn integer Traffic class.
function ipv6:get_traffclass ()
	return self.ip6_tc
end

--- Get packet's flowlabel.
-- @treturn integer Flowlabel.
function ipv6:get_flowlabel ()
	return self.ip6_fl
end

--- Get length of packet's payload.
-- @treturn integer Length.
function ipv6:get_payloadlen ()
	return self.ip6_plen
end

--- Get type of packet's next header.
-- @treturn integer Next header type. This field carries the same value as the protocol field in IPv4 packet header.
-- @see ipv6.proto
function ipv6:get_nexthdrtype ()
	return self.ip6_nhdr
end

--- Get packet's hop limit.
-- @treturn integer Hop limit.
function ipv6:get_hoplimit ()
	return self.ip6_hlimt
end

--- Get last error message.
-- @treturn string Error message.
function ipv6:get_error ()
	return self.errmsg or "no error"
end

return ipv6

