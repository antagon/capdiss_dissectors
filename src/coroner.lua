--- Main module.
-- @module coroner

-- Enable colors if stdout is writting to terminal.
if _STDOUT_TYPE == "chrdev" then
	require ("color")
else
	string.color = function (str)
		return str
	end
end

local coroner = {}
local coroner_ver = "1.0"

coroner.app = require ("app")

--- Create a new application of a given type.
-- @tparam integer type Type of an application.
-- @treturn table New application object.
-- @see app.type
function coroner.new_app (type)
	if not _CAPDISS_VERSION then
		error ("Sorry... Coroner Framework can only be run in capdiss environment.", 2)
	end

	return coroner.app:new (type)
end

--- Get version of the Coroner Framework.
-- treturn string Version.
function coroner.version ()
	local ver = coroner_ver
	return ver
end

--- Get version of capdiss environment in which the script is running.
-- return Version string or nil, if the version could not be determined.
function coroner.capdiss_version ()
	if _CAPDISS_VERSION then
		local _, _, ver = string.match (_CAPDISS_VERSION, "(%d.%d.%d)$")
		return ver
	end

	return nil
end

return coroner

