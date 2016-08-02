--- Intermediary application module.
-- @module app
local app = {}

--- Application types
app.type = {
	DISSECTOR = 0x01 -- Packet dissector
}

--- Create a new application of given type.
-- @tparam integer type Type of an application.
-- @treturn table New application object.
function app:new (type)
	local app_new = nil

	if type == app.type.DISSECTOR then
		app_new = require ("app/dissector")
	else
		error ("undefined application type", 2)
	end

	return app_new
end

return app

