--
-- SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
-- SPDX-License-Identifier: OSL-3.0
--

local ffi = require("ffi")
local neuropil = require("neuropil")

local Receiver = neuropil:new{}

Receiver:authorize(function (id)
   -- TODO: Make sure that id.public_key is the intended sender!
   return true
end)

Receiver:listen("udp4", "localhost", 3456)

Receiver:run(0.0)

Receiver:join("*:udp4:localhost:2345")

Receiver:receive("mysubject", function (message)
   print("Received: "..ffi.string(message.data, message.data_length))
   return true
end)

while true do
   Receiver:run(5)
end
