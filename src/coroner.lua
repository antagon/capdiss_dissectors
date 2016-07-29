--- Framework for network packet dissection.
-- @module coroner

local coroner = {}

coroner.app = {}

coroner.app.type = {
	DISSECTOR = 0x01
}

--- Create a new application.
-- @tparam type Type of an application.
-- @treturn table Application object.
function coroner.new_app (type)
	local app = nil

	if type == coroner.app.type.DISSECTOR then
		app = require ("app/dissector")
	end

	return app
end

return coroner

