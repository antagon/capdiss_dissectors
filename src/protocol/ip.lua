local ip = {}

ip.parse = function (buffer, offset)
	local tmp_ip = {}

	if type (buffer) ~= "string" then
		error ("parameter 'buffer' is not a string (got " .. type (buffer) .. ")")
	end

	if type (offset) ~= "number" and type (offset) ~= "nil" then
		error ("parameter 'offset' is not a number (got " .. type (offset) .. ")")
	end

	if offset then
		tmp_ip.offset = offset
	else
		tmp_ip.offset = 0
	end

	tmp_ip.version = ((buffer:byte (tmp_ip.offset + 1) & 0xF0) >> 4)
	tmp_ip.hdr_len = ((buffer:byte (tmp_ip.offset + 1) & 0x0F) << 2)

	tmp_ip.offset = tmp_ip.offset + 1

	-- Skip 'differentiated services' byte
	tmp_ip.offset = tmp_ip.offset + 1

	tmp_ip.tot_len = (buffer:byte (tmp_ip.offset + 1) << 8) | (buffer:byte (tmp_ip.offset + 2) & 0xFF)

	tmp_ip.offset = tmp_ip.offset + 2

	tmp_ip.id = (buffer:byte (tmp_ip.offset + 1) << 8) | (buffer:byte (tmp_ip.offset + 2) & 0xFF)

	tmp_ip.offset = tmp_ip.offset + 2

	tmp_ip.flags = buffer:byte (tmp_ip.offset + 1)

	-- Do not increment the offset, fragment offset begins at the same byte
	--tmp_ip.offset = tmp_ip.offset + 1

	tmp_ip.frag_off = (buffer:byte (tmp_ip.offset + 1) << 8) | (buffer:byte (tmp_ip.offset + 2) & 0xFF)

	tmp_ip.offset = tmp_ip.offset + 2

	tmp_ip.ttl = buffer:byte (tmp_ip.offset + 1)

	tmp_ip.offset = tmp_ip.offset + 1

	tmp_ip.proto = buffer:byte (tmp_ip.offset + 1)

	tmp_ip.offset = tmp_ip.offset + 1

	tmp_ip.checksum = (buffer:byte (tmp_ip.offset + 1) << 8) | (buffer:byte (tmp_ip.offset + 2) & 0xFF)

	tmp_ip.offset = tmp_ip.offset + 2

	tmp_ip.src = string.format ("%d.%d.%d.%d",
									buffer:byte (tmp_ip.offset + 1),
									buffer:byte (tmp_ip.offset + 2),
									buffer:byte (tmp_ip.offset + 3),
									buffer:byte (tmp_ip.offset + 4))

	tmp_ip.offset = tmp_ip.offset + 4

	tmp_ip.dst = string.format ("%d.%d.%d.%d",
									buffer:byte (tmp_ip.offset + 1),
									buffer:byte (tmp_ip.offset + 2),
									buffer:byte (tmp_ip.offset + 3),
									buffer:byte (tmp_ip.offset + 4))

	tmp_ip.offset = tmp_ip.offset + 4

	return tmp_ip
end

return ip

