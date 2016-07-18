local stdint = require ("stdint")
local eth = {
	ETHERTYPE_IP = 0x0800,
	ETHERTYPE_ARP = 0x0806,
	ETHERTYPE_IP6 = 0x86DD
}

local function eth_ntop (binstr)
	return ("%02x:%02x:%02x:%02x:%02x:%02x"):format (binstr:byte (1),
														binstr:byte (2),
														binstr:byte (3),
														binstr:byte (4),
														binstr:byte (5),
														binstr:byte (6))
end

function eth.new (frame)
	if type (frame) ~= "string" then
		error ("parameter 'frame' is not a string", 2)
	end

	local eth_frame = setmetatable ({}, { __index = eth })

	eth_frame.buff = frame

	return eth_frame
end

function eth:parse ()
	if not self.buff or string.len (self.buff) < 14 then
		self.errmsg = "incomplete Ethernet frame data"
		return false
	end

	self.mac_dst = string.sub (self.buff, 1, 6)
	self.mac_src = string.sub (self.buff, 7, 12)
	self.ether_type = stdint.u16 (self.buff, 12)

	return true
end

function eth:get_rawpacket ()
	if string.len (self.buff) > 14 then
		return string.sub (self.buff, 15, -1)
	end

	return ""
end

function eth:set_frame (frame)
	self.buff = frame
end

function eth:get_ethertype ()
	return self.ether_type
end

function eth:get_saddr ()
	return eth_ntop (self.mac_src)
end

function eth:get_daddr ()
	return eth_ntop (self.mac_dst)
end

function eth:get_error ()
	return self.errmsg or "no error"
end

return eth

