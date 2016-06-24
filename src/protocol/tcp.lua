local tcp = {}

tcp.parse = function (buffer, offset)
	local tmp_tcp = {}

	if type (buffer) ~= "string" then
		error ("parameter 'buffer' is not a string (got " .. type (buffer) .. ")", 2)
	end

	if type (offset) ~= "number" and type (offset) ~= "nil" then
		error ("parameter 'offset' is not a number (got " .. type (offset) .. ")", 2)
	end

	if offset then
		tmp_tcp.offset = offset
	else
		tmp_tcp.offset = 0
	end

	tmp_tcp.src = (buffer:byte (tmp_tcp.offset + 1) << 8) | (buffer:byte (tmp_tcp.offset + 2) & 0xFF)

	tmp_tcp.offset = tmp_tcp.offset + 2

	tmp_tcp.dst = (buffer:byte (tmp_tcp.offset + 1) << 8) | (buffer:byte (tmp_tcp.offset + 2) & 0xFF)

	tmp_tcp.offset = tmp_tcp.offset + 2

	--tmp_tcp.seq = (buffer:byte (tmp_tcp.offset + 1) )

	return tmp_tcp
end

return tcp

