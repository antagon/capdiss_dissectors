--- Intermediary application module.
-- @classmod coroner.app
local app = {}

--- Recognized application types.
-- @see coroner.app.dissector
app.type = {
	DISSECTOR = 0x01 -- Packet dissector
}

--- Create a new application of type _type_.
-- @tparam integer type Type of an application.
-- @treturn table New application object.
-- @see app.type
function app:new (type)
	local app_new = nil

	if type == app.type.DISSECTOR then
		app_new = require ("coroner/app/dissector")
	else
		error ("unrecognized application type", 2)
	end

	return app_new
end

return app

