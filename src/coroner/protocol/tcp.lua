--- Transmission Control Protocol (TCP) packet dissector.
-- This module is based on code adapted from nmap's nselib. See http://nmap.org/.
-- @classmod coroner.protocol.tcp
local bstr = require ("coroner/bstr")
local bit = require ("bit32")
local tcp = {}

local function raw (buff, index, length)
	if not index then index = 0 end
	if not length then length = #buff - index end

	return string.char(string.byte(buff, index+1, index+1+length-1))
end

local function tcp_parseopts (buff, offset, length)
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
				d = raw (buff, offset + opt_ptr + 2, l-2)
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
-- @tparam string packet byte string of packet data 
-- @treturn table New tcp table.
function tcp:new (packet)
	if type (packet) ~= "string" then
		error ("parameter 'packet' is not a string", 2)
	end

	local tcp_pkt = setmetatable ({}, { __index = tcp })

	tcp_pkt.buff = packet

	return tcp_pkt
end

--- Parse the packet data.
-- @treturn boolean True on success, false on failure (error message is set).
-- @see tcp:new
-- @see tcp:set_packet
function tcp:parse ()
	if self.buff == nil then
		self.errmsg = "no data"
		return false
	elseif string.len (self.buff) < 20 then
		self.errmsg = "incomplete TCP header data"
		return false
	end

	self.tcp_sport = bstr.u16 (self.buff, 0)
	self.tcp_dport = bstr.u16 (self.buff, 2)
	self.tcp_seq = bstr.u32 (self.buff, 4)
	self.tcp_ack = bstr.u32 (self.buff, 8)
	self.tcp_hl = bit.rshift (bit.band(bstr.u8(self.buff, 12), 0xF0), 4) * 4
	self.tcp_x2 = bit.band (bstr.u8 (self.buff, 12), 0x0F)
	self.tcp_flags = bstr.u8 (self.buff, 13)

	self.tcp_th = {}
	self.tcp_th["fin"] = bit.band(self.tcp_flags, 0x01) ~= 0 -- true/false
	self.tcp_th["syn"] = bit.band(self.tcp_flags, 0x02) ~= 0
	self.tcp_th["rst"] = bit.band(self.tcp_flags, 0x04) ~= 0
	self.tcp_th["push"] = bit.band(self.tcp_flags, 0x08) ~= 0
	self.tcp_th["ack"] = bit.band(self.tcp_flags, 0x10) ~= 0
	self.tcp_th["urg"] = bit.band(self.tcp_flags, 0x20) ~= 0
	self.tcp_th["ece"] = bit.band(self.tcp_flags, 0x40) ~= 0
	self.tcp_th["cwr"] = bit.band(self.tcp_flags, 0x80) ~= 0

	self.tcp_win = bstr.u16 (self.buff, 14)
	self.tcp_sum = bstr.u16 (self.buff, 16)
	self.tcp_urgp = bstr.u16 (self.buff, 18)
	self.tcp_opt_offset = 20
	self.tcp_options = tcp_parseopts (self.buff, self.tcp_opt_offset, (self.tcp_hl - 20))
	--self.tcp_data_len = string.len (self.buff) - self.tcp_hl

	return true
end

--- Get the module name.
-- @treturn string Module name.
function tcp:type ()
	return "tcp"
end

--- Get data encapsulated in a packet.
-- @treturn string Packet data or an empty string.
function tcp:get_data ()
	return string.sub (self.buff, self.tcp_hl + 1, -1)
end

--- Get length of data encapsulated in a packet.
-- @treturn integer Data length.
function tcp:get_datalen ()
	return string.len (self.buff) - self.tcp_hl
end

--- Change or set new packet data.
-- @tparam string packet byte string of packet data
function tcp:set_packet (packet)
	if type (packet) ~= "string" then
		error ("parameter 'packet' is not a string", 2)
	end

	self.buff = packet
end

--- Get packet's source port.
-- @treturn integer Source port.
function tcp:get_srcport ()
	return self.tcp_sport
end

--- Get packet's destination port.
-- @treturn integer Destination port.
function tcp:get_dstport ()
	return self.tcp_dport
end

--- Get packet's sequence number.
-- @treturn integer Sequence number.
function tcp:get_seqnum ()
	return self.tcp_seq
end

--- Get packet's acknowledgment number.
-- @treturn integer Acknowledgment number.
function tcp:get_acknum ()
	return self.tcp_ack
end

--- Get packet's header length.
-- @treturn integer Header length.
function tcp:get_hdrlen ()
	return self.tcp_hl
end

--- Get packet's flags.
-- @treturn table Flags.
function tcp:get_flags ()
	return self.tcp_th
end

--- Get packet's flags.
-- @treturn integer Flags.
function tcp:get_rawflags ()
	return self.tcp_flags
end

--- Check if the FIN flag is set in a packet.
-- @treturn boolean True if flag is set, otherwise False.
function tcp:isset_fin ()
	return self.tcp_th["fin"]
end

--- Check if the SYN flag is set in a packet.
-- @treturn boolean True if flag is set, otherwise False.
function tcp:isset_syn ()
	return self.tcp_th["syn"]
end

--- Check if the RST flag is set in a packet.
-- @treturn boolean True if flag is set, otherwise False.
function tcp:isset_rst ()
	return self.tcp_th["rst"]
end

--- Check if the PSH flag is set in a packet.
-- @treturn boolean True if flag is set, otherwise False.
function tcp:isset_push ()
	return self.tcp_th["push"]
end

--- Check if the ACK flag is set in a packet.
-- @treturn boolean True if flag is set, otherwise False.
function tcp:isset_ack ()
	return self.tcp_th["ack"]
end

--- Check if the URGENT flag is set in a packet.
-- @treturn boolean True if flag is set, otherwise False.
function tcp:isset_urg ()
	return self.tcp_th["urg"]
end

--- Check if the ECHO flag is set in a packet.
-- @treturn boolean True if flag is set, otherwise False.
function tcp:isset_echo ()
	return self.tcp_th["echo"]
end

--- Check if the CWR flag is set in a packet.
-- @treturn boolean True if flag is set, otherwise False.
function tcp:isset_cwr ()
	return self.tcp_th["cwr"]
end

--- Get packet's window size.
-- @treturn integer Window size.
function tcp:get_winsize ()
	return self.tcp_win
end

--- Get packet's checksum.
-- @treturn integer Checksum.
function tcp:get_checksum ()
	return self.tcp_sum
end

--- Get packet's value of the urgent pointer.
-- @treturn integer Urgent pointer.
function tcp:get_urgpointer ()
	return self.tcp_urgp
end

--- Get last error message.
-- @treturn string Error message.
function tcp:get_error ()
	return self.errmsg or "no error"
end

return tcp

