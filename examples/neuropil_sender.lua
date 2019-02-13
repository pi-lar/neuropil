--
-- neuropil is copyright 2016-2018 by pi-lar GmbH
-- Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
--

local neuropil = require("neuropil")

local Sender = neuropil:new{}

Sender:authorize(function (id)
   -- TODO: Make sure that id.public_key is the intended sender!
   return true
end)

Sender:listen("udp4", "localhost", 1234)

Sender:join("*:udp4:localhost:2345")

while true do
   Sender:send("mysubject", "Hello, World!")
   Sender:run(5)
end
