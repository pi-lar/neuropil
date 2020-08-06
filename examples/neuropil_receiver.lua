--
-- neuropil is copyright 2016-2018 by pi-lar GmbH
-- Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
--

local ffi = require("ffi")
local neuropil = require("neuropil")

local Receiver = neuropil:new{}

Receiver:authorize(function (id)
   -- TODO: Make sure that id.public_key is the intended sender!
   return true
end)

Receiver:listen("udp4", "localhost", 3456)

Receiver:join("*:udp4:localhost:2345")

Receiver:receive("mysubject", function (message)
   print("Received: "..ffi.string(message.data, message.data_length))
   return true
end)

while true do
   Receiver:run(5)
end
