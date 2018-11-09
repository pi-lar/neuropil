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

-- Example: receiving messages, in Lua.

local cfg = ffi.new('struct np_settings')
C.np_default_settings(cfg)

local ac = C.np_new_context(cfg)

assert(C.np_ok == C.np_listen(ac, "udp4", "localhost", 3456))

assert(C.np_ok == C.np_join(ac, "*:udp4:localhost:2345"))

function authorize (ac, id)
   -- TODO: Make sure that id->public_key is the intended sender!
   return true
end
assert(C.np_ok == C.np_set_authorize_cb(ac, authorize))

function receive (ac, message)
   print("Received: "..ffi.string(message[0].data, message[0].data_length))
   return true
end
assert(C.np_ok == C.np_add_receive_cb(ac, "mysubject", receive))

local status
repeat status = C.np_run(ac, 5) until C.np_ok ~= status

return tonumber(status)
