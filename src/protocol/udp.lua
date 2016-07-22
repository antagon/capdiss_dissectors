--- User Datagram Protocol (UDP) packet dissector.
-- This module is based on code adapted from nmap's nselib. See http://nmap.org/.
-- @module udp
local bstr = require ("bstr")
local udp = {}

--- Create a new object.
-- @tparam string packet byte string of packet data 
-- @treturn table New udp table.
function udp.new (packet)
	if type (packet) ~= "string" then
		error ("parameter 'packet' is not a string", 2)
	end

	local udp_pkt = setmetatable ({}, { __index = udp })

	udp_pkt.buff = packet

	return udp_pkt
end

--- Parse the packet data.
-- @treturn boolean True on success, false on failure (error message is set).
-- @see udp.new
-- @see udp:set_packet
function udp:parse ()
	if self.buff == nil then
		self.errmsg = "no data"
		return false
	elseif string.len (self.buff) < 8 then
		self.errmsg = "incomplete UDP header data"
		return false
	end

	self.udp_sport = bstr.u16 (self.buff, 0)
	self.udp_dport = bstr.u16 (self.buff, 2)
	self.udp_len = bstr.u16 (self.buff, 4)
	self.udp_sum = bstr.u16 (self.buff, 6)

	return true
end

--- Get data encapsulated in a packet.
-- @treturn string Packet data or an empty string.
function udp:get_data ()
	return string.sub (self.buff, 8 + 1, -1)
end

--- Get length of data encapsulated in a packet.
-- @treturn integer Data length.
function udp:get_datalen ()
	return self.udp_len - 8
end

--- Change or set new packet data.
-- @tparam string packet byte string of packet data
function udp:set_packet (packet)
	self.buff = packet
end

--- Get packet's source port.
-- @treturn integer Source port.
function udp:get_srcport ()
	return self.udp_sport
end

--- Get packet's destination port.
-- @treturn integer Destination port.
function udp:get_dstport ()
	return self.udp_dport
end

--- Get packet's length.
-- @treturn integer Packet length.
function udp:get_length ()
	return self.udp_len
end

--- Get packet's checksum.
-- @treturn integer Checksum.
function udp:get_checksum ()
	return self.udp_sum
end

--- Get last error message.
-- @treturn string Error message.
function udp:get_error ()
	return self.errmsg or "no error"
end

return udp

