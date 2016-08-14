--- HTTP (Hypertext Transfer Protocol) dissector.
-- @classmod coroner.protocol.http
local http = {}

--- Create a new object.
-- @tparam string packet pass packet data as an opaque string
-- @treturn table New http table.
function http:new (packet)
	if type (packet) ~= "string" then
		error ("parameter 'packet' is not a string", 2)
	end

	local http_pkt = setmetatable ({}, { __index = http })

	http_pkt.buff = packet

	return http_pkt
end

--- Parse the packet data.
-- @treturn boolean True on success, false on failure (error message is set).
-- @see http:new
-- @see http:set_packet
function http:parse ()
	self.http_method, self.http_uri, self.http_ver = self.buff:match ("^([GHPDOC]+[%a]+) (%g+) HTTP/(%d+.%d+)[\r\n]*")

	if self.http_method == nil or self.http_uri == nil then
		self.http_ver, self.http_code, self.http_resp = self.buff:match ("HTTP/(%d+.%d+) (%d+) ([%a ]*)[\r\n]*")
	end

	if self.http_method == nil and self.http_code == nil then
		self.errmsg = "invalid HTTP data"
		return false
	end

	self.http_hdr = {}

	-- Parse HTTP headers
	for name, val in self.buff:gmatch ("([%g]+)[ ]*:[ ]*([%g ]*)[\r\n]*") do
		self.http_hdr[name:lower ()] = val
	end

	return true
end

--- Get the module name.
-- @treturn string Module name.
function http:type ()
	return "http"
end

--- Change or set new packet data.
-- @tparam string packet byte string of packet data
function http:set_packet (packet)
	self.buff = packet
end

--- Check if parsed data is HTTP request.
-- @treturn boolean True/False.
function http:is_request ()
	return self.http_method ~= nil and self.http_uri ~= nil
end

--- Get HTTP version string.
-- @treturn string Returns either 1.1 or 1.0.
function http:get_version ()
	return self.http_ver
end

--- Get request method.
-- Calling this function makes sense only for HTTP requests.
-- @treturn string Name of the method or **nil**.
function http:get_method ()
	return self.http_method
end

--- Get URI specified in a request.
-- Calling this function makes sense only for HTTP requests.
-- @treturn string URI.
function http:get_uri ()
	return self.http_uri
end

--- Get response status code.
-- Calling this function makes sense only for HTTP responses.
-- @treturn integer Status code.
function http:get_statuscode ()
	return tonumber (self.http_code)
end

--- Get HTTP response.
-- Calling this function makes sense only for HTTP responses.
-- @treturn string Status code and response name.
function http:get_response ()
	return ("%s %s"):format (self.http_code, self.http_resp)
end

--- Get HTTP header field by name.
-- @tparam string name Lower-case name of the header field.
-- @treturn string Header field value or **nil**.
function http:get_header (name)
	return self.http_hdr[name]
end

--- Get last error message.
-- @treturn string Error message.
function http:get_error ()
	return self.errmsg or "no error"
end

return http

