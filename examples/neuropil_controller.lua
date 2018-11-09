--
-- neuropil is copyright 2016-2018 by pi-lar GmbH
-- Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
--

-- FFI boilerplate

-- Load FFI module
local ffi = require("ffi")
local C = ffi.C

-- Load Neuropil shared object into global namespace
ffi.load("build/lib/libneuropil.so", true)

-- Read Neuropil API
do local f = io.open("build/lib/libneuropil_ffi.h", "r")
   assert(f, "Unable to open: build/lib/libneuropil_ffi.h")
   ffi.cdef(f:read("*a"))
   f:close()
end

-- Example: bootstrap node, in Lua.

local cfg = ffi.new('struct np_settings')
C.np_default_settings(cfg)

local ac = C.np_new_context(cfg)

assert(C.np_ok == C.np_listen(ac, "udp4", "localhost", 2345))

local address
do
   local str = ffi.new("char[256]")
   assert(C.np_ok == C.np_get_address(ac, str, ffi.sizeof(str)))
   address = ffi.string(str)
end
print("Bootstrap address: "..address)

function authenticate (ac, id)
   -- TODO: Make sure that id->public_key is an authenticated peer!
   print(("Joined: %02X%02X%02X%02X%02X%02X%02X..."):format(
         id[0].public_key[0], id[0].public_key[1], id[0].public_key[2],
         id[0].public_key[3], id[0].public_key[4], id[0].public_key[5],
         id[0].public_key[6]))
   return true
end
assert(C.np_ok == C.np_set_authenticate_cb(ac, authenticate))

local status
repeat status = C.np_run(ac, 5) until C.np_ok ~= status

return tonumber(status)
