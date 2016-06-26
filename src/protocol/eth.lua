local eth = {}

eth.parse = function (buffer, pos)
	local tmp_eth = {}
	local buff_pos = nil

	if type (buffer) ~= "string" then
		error ("parameter 'buffer' is not a string (got " .. type (buffer) .. ")", 2)
	end

	if type (pos) ~= "number" and type (pos) ~= "nil" then
		error ("parameter 'pos' is not a number (got " .. type (pos) .. ")", 2)
	end

	if pos then
		buff_pos = pos
	else
		buff_pos = 1
	end

	tmp_eth.dst = string.format ("%02x:%02x:%02x:%02x:%02x:%02x",
									buffer:byte (buff_pos),
									buffer:byte (buff_pos + 1),
									buffer:byte (buff_pos + 2),
									buffer:byte (buff_pos + 3),
									buffer:byte (buff_pos + 4),
									buffer:byte (buff_pos + 5))

	buff_pos = buff_pos + 6

	tmp_eth.src = string.format ("%02x:%02x:%02x:%02x:%02x:%02x",
									buffer:byte (buff_pos),
									buffer:byte (buff_pos + 1),
									buffer:byte (buff_pos + 2),
									buffer:byte (buff_pos + 3),
									buffer:byte (buff_pos + 4),
									buffer:byte (buff_pos + 5))

	buff_pos = buff_pos + 6

	tmp_eth.proto = (buffer:byte (buff_pos) << 8) | (buffer:byte (buff_pos + 1) & 0xFF)

	buff_pos = buff_pos + 2

	return tmp_eth, buff_pos
end

return eth

