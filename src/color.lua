--- An extension of the default string library, providing a single function string.color.
-- Copyright (c) 2016 Jesse Paroz (https://github.com/jparoz/string.color)
-- @module color

--- Recognized color names.
-- @table colors
local colors = {
    black = nil,    -- Black
    red = nil,      -- Red
    green = nil,     -- Green
    yellow = nil,    -- Yellow
    blue = nil,      -- Blue
    magenta = nil,   -- Magenta
    cyan = nil,      -- Cyan
    white = nil,     -- White
    brblack = nil,   -- Bright Black
    brred = nil,     -- Bright Red
    brgreen = nil,   -- Bright Green
    bryellow = nil,  -- Bright Yellow
    brblue = nil,    -- Bright Blue
    brmagenta = nil, -- Bright Magenta
    brcyan = nil,    -- Bright Cyan
    brwhite = nil   -- Bright White
}

local FG = {
    black = 30,
    red = 31,
    green = 32,
    yellow = 33,
    blue = 34,
    magenta = 35,
    cyan = 36,
    white = 37,
    brblack = 90,
    brred = 91,
    brgreen = 92,
    bryellow = 93,
    brblue = 94,
    brmagenta = 95,
    brcyan = 96,
    brwhite = 97,
}

local BG = {
    black = 40,
    red = 41,
    green = 42,
    yellow = 43,
    blue = 44,
    magenta = 45,
    cyan = 46,
    white = 47,
    brblack = 100,   -- Bright black
    brred = 101,     -- Bright red
    brgreen = 102,   -- Bright green
    bryellow = 103,  -- Bright yellow
    brblue = 104,    -- Bright blue
    brmagenta = 105, -- Bright magenta
    brcyan = 106,    -- Bright cyan
    brwhite = 107,   -- Bright white
}

local function escape (n)
    return string.char(27)..'['..tostring(n)..'m'
end

if string then
	--- Change color of a string.
	-- @tparam string s a string.
	-- @tparam string f foreground color name.
	-- @tparam string b background color name.
	-- @tparam boolean bold use bold style.
	-- @tparam boolean underline underline the text.
	-- @tparam boolean swap swap foreground and backgroud colors.
	-- @see colors
	string.color = function (s, f, b, bold, underline, swap)
		local fg = FG[f] or 39
		local bg = BG[b] or 49
		s = escape(fg) .. escape(bg) .. s
		if bold then s = escape(1) .. s end
		if underline then s = escape(4) .. s end
		if swap then s = escape(7) .. s end
		s = s .. escape(0)
		return s
	end
else
	error ("standard string module has not been loaded!")
end

