--
-- SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
-- SPDX-License-Identifier: OSL-3.0
--

local neuropil = require("neuropil")

local Sender = neuropil:new{}

Sender:authorize(function (id)
   -- TODO: Make sure that id.public_key is the intended sender!
   return true
end)

Sender:listen("udp4", "localhost", 1234)

Sender:run(0)

Sender:join("*:udp4:localhost:2345")

while true do
   Sender:send("mysubject", "Hello, World!")
   Sender:run(5)
end
