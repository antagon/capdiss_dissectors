--- Dissector Application.
-- @module dissector
local dissector = {}

--- A list of supported link-types.
dissector.link_type = {
	EN10MB = true
}

--- A list of supported protocols.
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

local function is_specialhook (name)
	return name == "*" or name == "sigaction"
end

function dissector:set_hooks (hooks)
	for idx, func in pairs (hooks) do
		if type (func) ~= "function" then
			self.errmsg = ("a hook '%s' is not a function"):format (idx)
			return false
		end

		if not is_specialhook (idx) then
			if not dissector.proto[idx] then
				self.errmsg = ("protocol '%s' not supported"):format (idx)
				return false
			end
		end
	end

	dissector.usr_hook = hooks

	return true
end

local function merge_tables (t1, t2)
	for _, v in pairs (t2) do
		table.insert (t1, v)
	end

	return t1
end

local function parse_ip_packet (ip_obj)
	local proto_type = nil
	local proto = {}

	if ip_obj:get_version () == 4 then
		proto_type = ip_obj:get_protocol ()
	elseif ip_obj:get_version () == 6 then
		proto_type = ip_obj:get_nexthdrtype ()
	else
		return nil, "unknown IP version"
	end

	local proto_l4 = nil

	if proto_type == ip_obj.type.IPPROTO_TCP then
		proto_l4 = require ("protocol/tcp")
		proto_l4_name = "tcp"
	elseif proto_type == ip_obj.type.IPPROTO_UDP then
		proto_l4 = require ("protocol/udp")
		proto_l4_name = "udp"
	else
		-- TODO: some other protocols, here...
	end

	if proto_l4 then
		proto_l4:set_packet (ip_obj:get_rawpacket ())

		if not proto_l4:parse () then
			return nil, proto_l4:get_error ()
		end

		table.insert (proto, { name = proto_l4_name, data = proto_l4 })
	end

	return proto
end

local function parse_eth_frame (frame)
	local eth = require ("protocol/eth")
	local proto = {}

	eth:set_frame (frame)

	if not eth:parse () then
		return nil, eth:get_error ()
	end

	table.insert (proto, { name = "eth", data = eth })

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
			table.insert (proto, { name = "ip", data = ip })
		else
			table.insert (proto, { name = "ipv6", data = ip })
		end

		local ip_proto, errmsg = parse_ip_packet (ip)

		if not ip_proto then
			return nil, errmsg
		end

		merge_tables (proto, ip_proto)
	end

	return proto
end

--- Run application.
-- @treturn table
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
			for _, proto in ipairs (frame_proto) do
				-- If 'any' hook is set, execute it first...
				if dissector.usr_hook["*"] then
					dissector.usr_hook["*"] (proto.data)
				end

				if dissector.usr_hook[proto.name] then
					dissector.usr_hook[proto.name] (proto.data)
				end
			end
		else
			error (("parser failed: %s"):format (errmsg))
		end
	end

	-- Set signal handler, if it was set in a hook table.
	if self.usr_hook["sigaction"] then
		hooks.sigaction = self.usr_hook["sigaction"]
	end

	return hooks
end

--- Get last error message.
-- @treturn string Error message.
function dissector:get_error ()
	return self.errmsg or "no error"
end

return dissector

