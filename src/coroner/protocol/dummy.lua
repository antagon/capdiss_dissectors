--- Dummy protocol.
-- This class serves as a dummy class for protocols, for which there is no
-- dissector available.
-- @classmod coroner.protocol.dummy
local dummy = {}

--- Create a new object.
-- @tparam string packet byte string of packet data 
-- @treturn table New dummy table.
function dummy:new (packet)
	if type (packet) ~= "string" then
		error ("parameter 'packet' is not a string", 2)
	end

	local dummy_pkt = setmetatable ({}, { __index = dummy })

	dummy_pkt.buff = packet

	return dummy_pkt
end

--- Performs no operation. Defined only for compatibility with other
-- dissectors.
-- @treturn boolean Always returns True.
function dummy:parse ()
	return true
end

--- Get the module name.
-- @treturn string Module name.
function dummy:type ()
	return "?"
end

--- Get data in the internal buffer.
-- @treturn string Packet data or an empty string.
function dummy:get_rawpacket ()
	return self.buff or ""
end

--- Get data in the internal buffer.
-- It's an alias for dummy:get_rawpacket.
-- @treturn string Packet data or an empty string.
-- @see dummy:get_rawpacket
function dummy:get_data ()
	return self.buff or ""
end

--- Get length of data in the internal buffer.
-- @treturn integer Data length.
function dummy:get_datalen ()
	return string.len (self.buff)
end

--- Change or set new data in the internal buffer.
-- @tparam string packet byte string
function dummy:set_packet (packet)
	if type (packet) ~= "string" then
		error ("parameter 'packet' is not a string", 2)
	end

	self.buff = packet
end

--- Get last error message.
-- @treturn string Error message.
function dummy:get_error ()
	return self.errmsg or "no error"
end

return dummy

