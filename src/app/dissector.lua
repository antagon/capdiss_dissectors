--- A dissector application.
-- The module expects a table to be passed, populated with functions. Table
-- keys match a protocol name or a special symbol. The module goes through the
-- content of a capture file, frame by frame, dissecting individual packets
-- inside of a frame. If a hook is defined for a matching protocol or for a
-- special symbol, the hooked function is called.
-- @classmod dissector
local dissector = {}

--- A list of supported link-types.
dissector.link_type = {
	EN10MB = true
}

--- A list of supported protocols.
dissector.proto = {
	eth = true,  -- Ethernet II
	ip = true,   -- Internet protocol version 4
	ipv6 = true, -- Internet protocol version 6
	tcp = true,  -- Transmission Control Protocol (TCP)
	udp = true,  -- User Datagram Protocol (UDP)
	icmp = true  -- Internet Control Message Protocol (ICMP)
}

local function is_specialhook (name)
	return name == "@" or name == "."
		or name == "^" or name == "$"
		or name == "*"
end

--- Set a hook table where the key names correspond to a protocol name or a symbol.
--
-- **@** (at sign) -- run at the beginning of each input file, before any
-- frames are processed.
--
-- **.** (dot) -- run at the end of each input file, after all frames were processed.
--
-- **^** (caret) -- run for each frame before any packets inside the frame are
-- processed.
--
-- **$** (dollar sign) -- run for each frame after all packets inside a frame
-- were processed.
--
-- ***** (asterisk) -- run for any packet.
--
-- _protocol_ -- run for each occurence of a protocol matching the name _protocol_ (i.e. tcp).
-- @tparam table hooks A key in a table is used to match a protocol name or a
-- special hook name. The value stored in each key must be a function.
-- @treturn boolean True on success, false on failure (error message is set).
function dissector:set_hooks (hooks)
	if type (hooks) ~= "table" then
		error ("parameter 'hooks' is not a table", 2)
	end

	for idx, func in pairs (hooks) do
		if type (func) ~= "function" then
			self.errmsg = ("a hook '%s' is not a function"):format (idx)
			return false
		end

		if not is_specialhook (idx) then
			if not dissector.proto[idx] then
				self.errmsg = ("protocol '%s' is not supported"):format (idx)
				return false
			end
		end
	end

	dissector.usr_hook = hooks

	return true
end

--- Set a function that should be called if a signal is delivered.
-- @tparam function func Function to call.
-- @treturn boolean True on success, false on failure (error message is set).
function dissector:set_sigaction (func)
	if type (func) ~= "function" then
		self.errmsg = "signal action is not a function"
		return false
	end

	self.usr_hook["sigaction"] = func

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
	local proto_l4_name = ""

	-- TCP
	if proto_type == ip_obj.proto.IPPROTO_TCP then
		proto_l4 = require ("protocol/tcp")
		proto_l4_name = "tcp"

	-- UDP
	elseif proto_type == ip_obj.proto.IPPROTO_UDP then
		proto_l4 = require ("protocol/udp")
		proto_l4_name = "udp"

	-- ICMP
	elseif proto_type == ip_obj.proto.IPPROTO_ICMP then
		proto_l4 = require ("protocol/icmp")
		proto_l4_name = "icmp"

	-- Encapsulated IP or IPv6
	elseif proto_type == ip_obj.proto.IPPROTO_IPIP or proto_type == ip_obj.proto.IPPROTO_IPV6 then
		local ip_encaps = ip_obj:new (ip_obj:get_rawpacket ())

		if not ip_encaps:parse () then
			return nil, ip_encaps:get_error ()
		end

		if ip_obj:get_version () == 4 then
			table.insert (proto, { name = "ip", data = ip_encaps })
		else
			table.insert (proto, { name = "ipv6", data = ip_encaps })
		end

		local ip_encaps_proto, errmsg = parse_ip_packet (ip_encaps)

		if not ip_encaps_proto then
			return nil, errmsg
		end

		merge_tables (proto, ip_encaps_proto)
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

	local proto_l3 = nil
	local proto_l3_name = ""

	if eth:get_ethertype () == eth.ethertype.ETHERTYPE_IP then
		proto_l3 = require ("protocol/ip")
		proto_l3_name = "ip"
	elseif eth:get_ethertype () == eth.ethertype.ETHERTYPE_IPV6 then
		proto_l3 = require ("protocol/ipv6")
		proto_l3_name = "ipv6"
	end

	if proto_l3 then
		proto_l3:set_packet (eth:get_rawpacket ())

		if not proto_l3:parse () then
			return nil, ip:get_error ()
		end

		table.insert (proto, { name = proto_l3_name, data = proto_l3 })

		if proto_l3_name == "ip" or proto_l3_name == "ipv6" then
			local ip_proto, errmsg = parse_ip_packet (proto_l3)

			if not ip_proto then
				return nil, errmsg
			end

			merge_tables (proto, ip_proto)
		end
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

		if dissector.usr_hook["@"] then
			dissector.usr_hook["@"] (filename, linktype)
		end
	end

	hooks.each = function (frame, ts, num)
		local dissector = self
		local frame_proto = nil
		local errmsg = ""

		if dissector.opts.linktype == "EN10MB" then
			frame_proto, errmsg = parse_eth_frame (frame)
		end

		if frame_proto then
			--
			-- Execute user hooks
			--
			if dissector.usr_hook["^"] then
				dissector.usr_hook["^"] (ts, num)
			end

			for _, proto in ipairs (frame_proto) do
				-- Execute 'any' hook first...
				if dissector.usr_hook["*"] then
					dissector.usr_hook["*"] (proto.data, ts, num)
				end

				if dissector.usr_hook[proto.name] then
					dissector.usr_hook[proto.name] (proto.data, ts, num)
				end
			end

			if dissector.usr_hook["$"] then
				dissector.usr_hook["$"] (ts, num)
			end
		else
			error (("parser failed: %s"):format (errmsg))
		end
	end

	-- Set finish hook, if it was set in a hook table.
	if self.usr_hook["."] then
		hooks.finish = self.usr_hook["."]
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

