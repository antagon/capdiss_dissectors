--- Main module.
-- @module coroner
local coroner = {}
local coroner_ver = "1.0"

coroner.app = require ("app")

--- Create a new application of a given type.
-- @tparam integer type Type of an application.
-- @treturn table New application object.
-- @see app.type
function coroner.new_app (type)
	return coroner.app:new (type)
end

--- Get version of the framework.
-- @treturn string Version.
function coroner.version ()
	local ver = coroner_ver
	return ver
end

--- Get version of capdiss environment.
-- @return Version string or **nil**.
function coroner.capdiss_version ()
	if _CAPDISS_VERSION then
		return string.match (_CAPDISS_VERSION, "(%d.%d.%d)$")
	end

	return nil
end

--- Determine if, and how stdout was redirected (file/another program,...).
-- @return One of the following values: _socket_, _file_,
-- _chrdev_, _blkdev_, _fifo_, _unknown_ or **nil**.
function coroner.get_stdout_type ()
	return _STDOUT_TYPE
end

--- Get type of an operating system.
-- @return One of the following values: _linux_, _windows_, _unknown_ or
-- **nil**.
function coroner.get_os_type ()
	return _OS
end

--- Enable/Disable ASCII colors. On Linux, colors are enabled by default.
function coroner.enable_colors (enable)
	if enable then
		require ("color")
	else
		-- If colors are disabled, return the original text.
		if string then
			string.color = function (str)
				return str
			end
		end
	end
end

local function check_compatibility (min_ver)
	local capdiss_ver = coroner.capdiss_version ()

	if not capdiss_ver then
		error ("Coroner can run only in the capdiss environment.", 2)
	else
		local capdiss_major, capdiss_minor = string.match (capdiss_ver, "^(%d+).(%d+).%d+$")
		local support_major, support_minor = string.match (min_ver, "^(%d+).(%d+).*%d*$")

		if tonumber (capdiss_major) < tonumber (support_major)
				or tonumber (capdiss_minor) < tonumber (support_minor) then
			error (("Coroner supports capdiss version >= %d.%d (current %d.%d)"):format (
						support_major, support_minor,
						capdiss_major, capdiss_minor), 2)
		end
	end
end

-- Check compability with capdiss environment.
check_compatibility ("0.3")

-- Enable colors if stdout is redirected to a terminal.
-- Windows terminal is not capable of displaying ASCII colors, so this feature
-- is disabled by default.
if coroner.get_stdout_type () == "chrdev" and coroner.get_os_type () ~= "windows" then
	coroner.enable_colors (true)
else
	coroner.enable_colors (false)
end

return coroner

