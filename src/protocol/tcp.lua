local tcp = {}

tcp.parse = function (buffer, pos)
	local tmp_tcp = {}
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

	tmp_tcp.src = (buffer:byte (buff_pos) << 8) | (buffer:byte (buff_pos + 1) & 0xFF)

	buff_pos = buff_pos + 2

	tmp_tcp.dst = (buffer:byte (buff_pos) << 8) | (buffer:byte (buff_pos + 1) & 0xFF)

	buff_pos = buff_pos + 2

	--tmp_tcp.seq = (buffer:byte (buff_pos + 1) )

	return tmp_tcp, buff_pos
end

return tcp

