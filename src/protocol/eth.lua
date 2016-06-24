local eth = {}

eth.parse = function (buffer, offset)
	local tmp_eth = {}

	if type (buffer) ~= "string" then
		error ("parameter 'buffer' is not a string (got " .. type (buffer) .. ")")
	end

	if type (offset) ~= "number" and type (offset) ~= "nil" then
		error ("parameter 'offset' is not a number (got " .. type (offset) .. ")")
	end

	if offset then
		tmp_eth.offset = offset
	else
		tmp_eth.offset = 0
	end

	tmp_eth.dst = string.format ("%02x:%02x:%02x:%02x:%02x:%02x",
									buffer:byte (tmp_eth.offset + 1),
									buffer:byte (tmp_eth.offset + 2),
									buffer:byte (tmp_eth.offset + 3),
									buffer:byte (tmp_eth.offset + 4),
									buffer:byte (tmp_eth.offset + 5),
									buffer:byte (tmp_eth.offset + 6))

	tmp_eth.offset = tmp_eth.offset + 6

	tmp_eth.src = string.format ("%02x:%02x:%02x:%02x:%02x:%02x",
									buffer:byte (tmp_eth.offset + 1),
									buffer:byte (tmp_eth.offset + 2),
									buffer:byte (tmp_eth.offset + 3),
									buffer:byte (tmp_eth.offset + 4),
									buffer:byte (tmp_eth.offset + 5),
									buffer:byte (tmp_eth.offset + 6))

	tmp_eth.offset = tmp_eth.offset + 6

	tmp_eth.proto = (buffer:byte (tmp_eth.offset + 1) << 8) | (buffer:byte (tmp_eth.offset + 2) & 0xFF)

	tmp_eth.offset = tmp_eth.offset + 2

	return tmp_eth
end

return eth

