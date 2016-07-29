--- Ethernet II frame dissector.
-- This module is based on code adapted from nmap's nselib. See http://nmap.org/.
-- @module eth

local bstr = require ("bstr")

local eth = {}

--- EtherType constants.
-- @see eth:get_ethertype
eth.type = {
	ETHERTYPE_IP = 0x0800, -- Internet Protocol version 4
	ETHERTYPE_ARP = 0x0806, -- Address Resolution Protocol
	ETHERTYPE_IPV6 = 0x86DD -- Internet Protocol version 6
}

local function eth_ntop (binstr)
	return ("%02x:%02x:%02x:%02x:%02x:%02x"):format (binstr:byte (1),
														binstr:byte (2),
														binstr:byte (3),
														binstr:byte (4),
														binstr:byte (5),
														binstr:byte (6))
end

--- Create a new object.
-- @tparam string frame pass frame data as an opaque string
-- @treturn table New eth table.
function eth.new (frame)
	if type (frame) ~= "string" then
		error ("parameter 'frame' is not a string", 2)
	end

	local eth_frame = setmetatable ({}, { __index = eth })

	eth_frame.buff = frame

	return eth_frame
end

--- Parse frame data.
-- @treturn boolean True on success, false on failure (error message is set).
-- @see eth.new
-- @see eth:set_frame
function eth:parse ()
	if self.buff == nil then
		self.errmsg = "no data"
		return false
	elseif string.len (self.buff) < 14 then
		self.errmsg = "incomplete Ethernet frame data"
		return false
	end

	self.mac_dst = string.sub (self.buff, 1, 6)
	self.mac_src = string.sub (self.buff, 7, 12)
	self.ether_type = bstr.u16 (self.buff, 12)

	return true
end

--- Get the module name.
-- @treturn string Module name.
function eth:type ()
	return "eth"
end

--- Get raw packet data encapsulated in the frame data.
-- @treturn string Raw packet data or an empty string.
function eth:get_rawpacket ()
	if string.len (self.buff) > 14 then
		return string.sub (self.buff, 15, -1)
	end

	return ""
end

--- Change or set new frame data.
-- @tparam string frame pass frame data as an opaque string
function eth:set_frame (frame)
	if type (frame) ~= "string" then
		error ("parameter 'frame' is not a string", 2)
	end

	self.buff = frame
end

--- Get EtherType value from the parsed content.
-- @treturn integer Value representing a type of encapsulated packet.
-- @see eth.type
function eth:get_ethertype ()
	return self.ether_type
end

--- Get source MAC address from the parsed content.
-- @treturn string MAC address formatted as xx:xx:xx:xx:xx:xx string.
function eth:get_saddr ()
	return eth_ntop (self.mac_src)
end

--- Get destination MAC address from the parsed content.
-- @treturn string MAC address formatted as xx:xx:xx:xx:xx:xx string.
function eth:get_daddr ()
	return eth_ntop (self.mac_dst)
end

--- Get source MAC address from the parsed content.
-- @treturn string Byte string representing a MAC address.
function eth:get_rawsaddr ()
	return self.mac_src
end

--- Get destination MAC address from the parsed content.
-- @treturn string Byte string representing a MAC address.
function eth:get_rawdaddr ()
	return self.mac_dst
end

--- Get last error message.
-- @treturn string Error message.
function eth:get_error ()
	return self.errmsg or "no error"
end

return eth

