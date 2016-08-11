--- Functions for byte string manipulation.
-- These functions were adapted from nmap's nselib. See http://nmap.org/.
-- @module coroner.bstr
local bstr = {}

--- Get an 8-bit integer at a 0-based byte offset in a byte string.
-- @tparam string b a byte string
-- @tparam integer i offset
-- @return An 8-bit integer.
function bstr.u8 (b, i)
  return string.byte(b, i+1)
end

--- Get a 16-bit integer at a 0-based byte offset in a byte string.
-- @tparam string b a byte string
-- @tparam integer i offset
-- @return A 16-bit integer.
function bstr.u16 (b, i)
  local b1,b2
  b1, b2 = string.byte(b, i+1), string.byte(b, i+2)
  --        2^8     2^0
  return b1*256 + b2
end

--- Get a 32-bit integer at a 0-based byte offset in a byte string.
-- @tparam string b a byte string
-- @tparam integer i offset
-- @return A 32-bit integer.
function bstr.u32(b,i)
  local b1,b2,b3,b4
  b1, b2 = string.byte(b, i+1), string.byte(b, i+2)
  b3, b4 = string.byte(b, i+3), string.byte(b, i+4)
  --        2^24          2^16       2^8     2^0
  return b1*16777216 + b2*65536 + b3*256 + b4
end

-- FIXME: this probably does not work!!!

--- Set an 8-bit integer at a 0-based byte offset in a byte string
-- (big-endian).
-- @tparam string b a byte string.
-- @tparam integer i offset.
-- @tparam integer num integer to store.
function bstr.set_u8(b, i, num)
  local s = string.char(bit.band(num, 0xff))
  return b:sub(0+1, i+1-1) .. s .. b:sub(i+1+1)
end

-- FIXME: this probably does not work!!!

--- Set a 16-bit integer at a 0-based byte offset in a byte string
-- (big-endian).
-- @param b A byte string.
-- @param i Offset.
-- @param num Integer to store.
function bstr.set_u16(b, i, num)
  local s = string.char(bit.band(bit.rshift(num, 8), 0xff)) .. string.char(bit.band(num, 0xff))
  return b:sub(0+1, i+1-1) .. s .. b:sub(i+1+2)
end

-- FIXME: this probably does not work!!!

--- Set a 32-bit integer at a 0-based byte offset in a byte string
-- (big-endian).
-- @param b A byte string.
-- @param i Offset.
-- @param num Integer to store.
function bstr.set_u32(b,i, num)
  local s = string.char(bit.band(bit.rshift(num,24), 0xff)) ..
  string.char(bit.band(bit.rshift(num,16), 0xff)) ..
  string.char(bit.band(bit.rshift(num,8), 0xff)) ..
  string.char(bit.band(num, 0xff))
  return b:sub(0+1, i+1-1) .. s .. b:sub(i+1+4)
end

-- FIXME: this probably does not work!!!

--- Get a 1-byte string from a number.
-- @tparam integer num a number.
function bstr.numtostr8(num)
  return string.char(num)
end

-- FIXME: this probably does not work!!!

--- Get a 2-byte string from a number.
-- (big-endian)
-- @tparam integer num a number.
function bstr.numtostr16(num)
  return set_u16("..", 0, num)
end

-- FIXME: this probably does not work!!!

--- Get a 4-byte string from a number.
-- (big-endian)
-- @tparam integer num a number.
function bstr.numtostr32(num)
  return set_u32("....", 0, num)
end

return bstr

