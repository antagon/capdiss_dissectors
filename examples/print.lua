local coroner = require ("coroner")
local app = coroner.new_app (coroner.app.type.DISSECTOR)

local hooks = {
	-- Match an Ethernet frame...
	eth = function (packet, ts, num)
		print (("[%06d] %s :: %s => %s"):format (
				num,
				packet:type ():upper (),
				packet:get_saddr ():color ("brblue", nil),
				packet:get_daddr ():color ("brblue", nil)))
	end,

	-- Match an IP packet...
	ip = function (packet, ts, num)
		print (("[%06d] %s :: %s => %s"):format (
				num,
				packet:type ():upper (),
				packet:get_saddr ():color ("brgreen", nil, true),
				packet:get_daddr ():color ("brgreen", nil, true)))
	end,

	ipv6 = function (packet, ts, num)
		print (("[%06d] %s :: %s => %s"):format (
				num,
				packet:type ():upper (),
				packet:get_saddr ():color ("brgreen", nil, true),
				packet:get_daddr ():color ("brgreen", nil, true)))
	end,

	-- Match a TCP packet...
	tcp = function (packet, ts, num)
		print (("[%06d] %s :: %s => %s"):format (
				num,
				packet:type ():upper (),
				tostring (packet:get_srcport ()):color ("bryellow", nil),
				tostring (packet:get_dstport ()):color ("bryellow", nil)))
	end,

	-- Match a UDP packet...
	udp = function (packet, ts, num)
		print (("[%06d] %s :: %s => %s"):format (num, packet:type ():upper (), packet:get_srcport (), packet:get_dstport ()))
	end,

	-- Trigger for each input file...
	["@"] = function (filename, linktype)
		print (("Reading %s (%s)..."):format (filename, linktype))
	end,

	-- Trigger after the last frame from input file was read...
	["."] = function ()
		print ("Done!")
	end,

	-- Trigger at the beginning of each frame...
	["^"] = function (ts, num)
		print (("Frame captured on %s"):format (os.date ("%Y-%m-%d %H:%M:%S", ts)))
	end,

	-- Match any packet...
	["*"] = function (packet, ts, num)
		-- Just here to show you that I exist...
	end,

	-- Trigger after end of each frame...
	["$"] = function (ts, num)
		-- Just here to show you that I exist...
	end,

	-- A signal handler...
	sigaction = function (signo)
		print ("Ooops... a signal delivered...")
	end
}

if not app:set_hooks (hooks) then
	error (app:get_error ())
end

return app:run ()

