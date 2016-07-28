local dissector = {}

dissector.link_type = {
	EN10MB = true
}

dissector.proto = {
	eth = true,
	ip = true,
	tcp = true,
	udp = true
}

function dissector.new ()
	local new_diss = setmetatable ({}, { __index = dissector })

	return new_diss
end

function dissector:set_hooks (hooks)
	for idx, func in pairs (hooks) do
		if not dissector.proto[idx] then
			self.errmsg = ("protocol '%s' not supported"):format (idx)
			return false
		end

		if type (func) ~= "function" then
			self.errmsg = ("a hook for protocol '%s' is not a function"):format (idx)
			return false
		end
	end

	dissector.hooks = hooks

	return true
end

local function parse_ip_packet (version, packet)
end

local function parse_eth_frame (frame)
	local eth = require ("protocol/eth")
	local proto = {}

	eth:set_frame (frame)

	if not eth:parse () then
		return nil, eth:get_error ()
	end

	proto["eth"] = eth

	local ip = nil

	if eth:get_ethertype () == eth.type.ETHERTYPE_IP then
		ip = require ("protocol/ip")
	elseif eth:get_ethertype () == eth.type.ETHERTYPE_IPV6 then
		ip = require ("protocol/ipv6")
	end

	if ip then
		ip:set_packet (eth:get_rawpacket ())

		if not ip:parse () then
			return nil, ip:get_error ()
		end

		if ip:get_version () == 4 then
			proto["ip"] = ip
		else
			proto["ipv6"] = ip
		end

		-- TODO: parse transport protocol
	end

	return proto
end

function dissector:run ()
	local hooks = {}

	hooks.begin = function (filename, linktype)
		local dissector = self

		if not dissector.link_type[linktype] then
			error (("unsupported linktype '%s'"):format (linktype))
		end

		dissector.opts = { filename = filename, linktype = linktype }
	end

	hooks.each = function (frame, ts, num)
		local dissector = self
		local frame_proto = nil
		local errmsg = ""

		if dissector.opts.linktype == "EN10MB" then
			frame_proto, errmsg = parse_eth_frame (frame)
		end

		if frame_proto then
			for name, packet in pairs (frame_proto) do
				if dissector.hook[name] then
					dissector.hook[name] (packet)
				end
			end
		else
			error (("parser failed: %s"):format (errmsg))
		end
	end

	hooks.finish = function ()
		local dissector = self
	end

	hooks.sigaction = function ()
		local dissector = self
	end

	return hooks
end

function dissector:get_error ()
	return self.errmsg
end

return dissector

