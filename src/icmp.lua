--- Internet Control Message Protocol (ICMP) packet dissector.
-- This module is based on code adapted from nmap's nselib. See http://nmap.org/.
-- @module icmp
local bstr = require ("bstr")
local icmp = {}

--- ICMP message types.
icmp.type = {
	ICMP_ECHOREPLY = 0,       -- Echo reply
	ICMP_DEST_UNREACH = 3,    -- Destination unreachable
	ICMP_SOURCE_QUENCH = 4,   -- Source quench
	ICMP_REDIRECT = 5,        -- Redirect (change route)
	ICMP_ECHO = 8,            -- Echo request
	ICMP_ROUTERADVERT = 9,    -- Router advertisement
	ICMP_ROUTERSOLICIT = 10,  -- Router solicitation
	ICMP_TIME_EXCEEDED = 11,  -- Time exceeded
	ICMP_PARAMPROB = 12,      -- Parameter problem
	ICMP_TIMESTAMP = 13,      -- Timestamp request
	ICMP_TIMESTAMPREPLY = 14, -- Timestamp reply
	ICMP_INFO_REQUEST = 15,   -- Information request
	ICMP_INFO_REPLY = 16,     -- Information reply
	ICMP_ADDRESS = 17,        -- Address Mask request
	ICMP_ADDRESSREPLY = 18,   -- Address Mask reply
	ICMP_TRACEROUTE = 30,     -- Traceroute
	ICMP_CONVERR = 31,        -- Conversion error
	ICMP_DOMAIN = 37,         -- Domain Name request
	ICMP_DOMAINREPLY = 38     -- Domain Name reply
}

--- ICMP message type codes.
icmp.code = {
	ICMP_NET_UNREACH = 0,          -- Network unreachable
	ICMP_HOST_UNREACH = 1,         -- Host unreachable
	ICMP_PROT_UNREACH = 2,         -- Protocol unreachable
	ICMP_PORT_UNREACH = 3,         -- Port unreachable
	ICMP_FRAG_NEEDED = 4,          -- Packet fragmentation is required but the DF bit in the IP header is set
	ICMP_SR_FAILED = 5,            -- Source route failed
	ICMP_NET_UNKNOWN = 6,          -- Destination network unknown
	ICMP_HOST_UNKNOWN = 7,         -- Destination host unknown
	ICMP_HOST_ISOLATED = 8,        -- Source host isolated
	ICMP_NET_ANO = 9,              -- The destination network is administratively prohibited
	ICMP_HOST_ANO = 10,            -- The destination host is administratively prohibited
	ICMP_NET_UNR_TOS = 11,         -- The network is unreachable for TOS
	ICMP_HOST_UNR_TOS = 12,        -- The host is unreachable for TOS
	ICMP_PKT_FILTERED = 13,        -- Packet filtered
	ICMP_PREC_VIOLATION = 14,      -- Host precedence violation
	ICMP_PREC_CUTOFF = 15,         -- Precedence cutoff in effect

	ICMP_ROUTERADVERT_NORMAL = 0,   -- Normal router advertisement
	ICMP_ROUTERADVERT_NROUTE = 16, -- Does not route common traffic

	ICMP_REDIR_NET = 0,            -- Network error
	ICMP_REDIR_HOST = 1,           -- Host error
	ICMP_REDIR_NETTOS = 2,         -- TOS and network error
	ICMP_REDIR_HOSTTOS = 3,        -- TOS and host error

	ICMP_EXC_TTL = 0,              -- Time to live exceeded during transit
	ICMP_EXC_FRAGTIME = 1,         -- Fragment reassembly timeout

	ICMP_INVALIDIPHDR = 0,         -- Invalid IP header
	ICMP_OPTMISSING = 1,           -- A required option is missing

	ICMP_PKTFORWSUCCESS = 0,       -- Outbound packet successfully forwarded
	ICMP_PKTNOROUTE = 1,           -- No route for outbound packet

	ICMP_ERRUNKNOWN = 0,           -- Unknown or unspecified error
	ICMP_NOCONVERTOPT = 1,         -- Don't convert option present
	ICMP_UNKNOWNOPT = 2,           -- Unknown mandatory option present
	ICMP_KNOWNOPTNSUPPORTED = 3,   -- Known unsupported option present
	ICMP_NSUPPTRANSPROTO = 4,      -- Unsupported transport protocol
	ICMP_LENGTHEXC = 5,            -- Overall length exceeded
	ICMP_IPHDRLENGTHEXC = 6,       -- IP header length exceeded
	ICMP_TRANSPROTOEXC = 7,        -- Transport protocol > 255
	ICMP_PORTCONVOUTOFRANGE = 8,   -- Port conversion out of range
	ICMP_TRANSHDRLENGTEXC = 9,     -- Transport header length exceeded
	ICMP_ROLLOVERMISSING = 10,     -- 32-bit rollover missing and ACK set
	ICMP_TRANSOPTMISSING = 11,     -- Unknown mandatory transport option present
}

--- Create a new object.
-- @tparam string packet byte string of packet data 
-- @treturn table New icmp table.
function icmp.new (packet)
	if type (packet) ~= "string" then
		error ("parameter 'packet' is not a string", 2)
	end

	local icmp_pkt = setmetatable ({}, { __index = icmp })

	icmp_pkt.buff = packet

	return icmp_pkt
end

--- Parse the packet data.
-- @treturn boolean True on success, false on failure (error message is set).
-- @see icmp.new
-- @see icmp:set_packet
function icmp:parse ()
	if string.len (self.buff) < 8 then
		self.errmsg = "incomplete ICMP header data"
		return false
	end

	self.icmp_type = bstr.u8 (self.buff, 1)
	self.icmp_code = bstr.u8 (self.buff, 2)
	self.icmp_sum = bstr.u16 (self.buff, 3)

	return true
end

--- Get data encapsulated in a packet.
-- @treturn string Packet data or an empty string.
function icmp:get_data ()
	return string.sub (self.buff, 8 + 1, -1)
end

--- Get length of data encapsulated in a packet.
-- @treturn integer Data length.
function icmp:get_datalen ()
	return string.len (self.buff) - 8
end

--- Change or set new packet data.
-- @tparam string packet byte string of packet data
function icmp:set_packet (packet)
	self.buff = packet
end

--- Get packet type.
-- @treturn integer Packet type.
-- @see icmp.type
function icmp:get_type ()
	return self.icmp_type
end

--- Get packet code.
-- @treturn integer Packet code.
-- @see icmp.code
-- @see icmp.code_to_text
function icmp:get_code ()
	return self.icmp_code
end

--- Get packet's checksum.
-- @treturn integer Packet checksum.
function icmp:get_checksum ()
	return self.icmp_sum
end

--- Translate packet's type and code number to text.
-- @tparam integer type Packet type.
-- @tparam integer code Packet code.
-- @treturn string Message or nil, if combination of type and code does not exists.
-- @see icmp.type
-- @see icmp.code
function icmp.code_to_text (type, code)
	local types = {}

	types[ICMP_DEST_UNREACH][ICMP_NET_UNREACH] = "Network unreachable"
	types[ICMP_DEST_UNREACH][ICMP_HOST_UNREACH] = "Host unreachable"
	types[ICMP_DEST_UNREACH][ICMP_PROT_UNREACH] = "Protocol unreachable"
	types[ICMP_DEST_UNREACH][ICMP_PORT_UNREACH] = "Port unreachable"
	types[ICMP_DEST_UNREACH][ICMP_FRAG_NEEDED] = "Packet fragmentation is required but the DF bit in the IP header is set"
	types[ICMP_DEST_UNREACH][ICMP_SR_FAILED] = "Source route failed"
	types[ICMP_DEST_UNREACH][ICMP_NET_UNKNOWN] = "Destination network unknown"
	types[ICMP_DEST_UNREACH][ICMP_HOST_UNKNOWN] = "Destination host unknown"
	types[ICMP_DEST_UNREACH][ICMP_HOST_ISOLATED] = "Source host isolated"
	types[ICMP_DEST_UNREACH][ICMP_NET_ANO] = "The destination network is administratively prohibited"
	types[ICMP_DEST_UNREACH][ICMP_HOST_ANO] = "The destination host is administratively prohibited"
	types[ICMP_DEST_UNREACH][ICMP_NET_UNR_TOS] = "The network is unreachable for TOS"
	types[ICMP_DEST_UNREACH][ICMP_HOST_UNR_TOS] = "The host is unreachable for TOS"
	types[ICMP_DEST_UNREACH][ICMP_PKT_FILTERED] = "Packet filtered"
	types[ICMP_DEST_UNREACH][ICMP_PREC_VIOLATION] = "Host precedence violation"
	types[ICMP_DEST_UNREACH][ICMP_PREC_CUTOFF] = "Precedence cutoff in effect"

	types[ICMP_ROUTERADVERT][ICMP_ROUTERADVERT_NORMAL] = "Normal router advertisement"
	types[ICMP_ROUTERADVERT][ICMP_ROUTERADVERT_NROUTE] = "Does not route common traffic"

	types[ICMP_REDIRECT][ICMP_REDIR_NET] = "Network error"
	types[ICMP_REDIRECT][ICMP_REDIR_HOST] = "Host error"
	types[ICMP_REDIRECT][ICMP_REDIR_NETTOS] = "TOS and network error"
	types[ICMP_REDIRECT][ICMP_REDIR_HOSTTOS] = "TOS and host error"

	types[ICMP_TIME_EXCEEDED][ICMP_EXC_TTL] = "Time to live exceeded during transit"
	types[ICMP_TIME_EXCEEDED][ICMP_EXC_FRAGTIME] = "Fragment reassembly timeout"

	types[ICMP_PARAMPROB][ICMP_INVALIDIPHDR] = "Invalid IP header"
	types[ICMP_PARAMPROB][ICMP_OPTMISSING] = "A required option is missing"

	types[ICMP_TRACEROUTE][ICMP_PKTFORWSUCCESS] = "Outbound packet successfully forwarded"
	types[ICMP_TRACEROUTE][ICMP_PKTNOROUTE] = "No route for outbound packet"

	types[ICMP_CONVERR][ICMP_ERRUNKNOWN] = "Unknown or unspecified error"
	types[ICMP_CONVERR][ICMP_NOCONVERTOPT] = "Don't convert option present"
	types[ICMP_CONVERR][ICMP_UNKNOWNOPT] = "Unknown mandatory option present"
	types[ICMP_CONVERR][ICMP_KNOWNOPTNSUPPORTED] = "Known unsupported option present"
	types[ICMP_CONVERR][ICMP_NSUPPTRANSPROTO] = "Unsupported transport protocol"
	types[ICMP_CONVERR][ICMP_LENGTHEXC] = "Overall length exceeded"
	types[ICMP_CONVERR][ICMP_IPHDRLENGTHEXC] = "IP header length exceeded"
	types[ICMP_CONVERR][ICMP_TRANSPROTOEXC] = "Transport protocol > 255"
	types[ICMP_CONVERR][ICMP_PORTCONVOUTOFRANGE] = "Port conversion out of range"
	types[ICMP_CONVERR][ICMP_TRANSHDRLENGTEXC] = "Transport header length exceeded"
	types[ICMP_CONVERR][ICMP_ROLLOVERMISSING] = "32-bit rollover missing and ACK set"
	types[ICMP_CONVERR][ICMP_TRANSOPTMISSING] = "Unknown mandatory transport option present"

	if types[type] then
		return types[type][code]
	end

	return nil
end

return icmp

