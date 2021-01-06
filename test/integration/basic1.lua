--
-- neuropil is copyright 2016-2021 by pi-lar GmbH
-- Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
--

-- Test basic controller/sender/receiver triangle.

local ffi = require("ffi")
local neuropil = require("neuropil")

local Controller = neuropil:new{}
Controller:authenticate(function (id)
   print(("Joined: %02X%02X%02X%02X%02X%02X%02X..."):format(
         id.public_key[0], id.public_key[1], id.public_key[2],
         id.public_key[3], id.public_key[4], id.public_key[5],
         id.public_key[6]))
   return true
end)
-- XXX: Controller needs explicit port because get_address returns a bogus
-- address when listening on the default port.
Controller:listen("udp4", "localhost", 4242)

local test_subject, test_data = "test", "Test, eins zwei, eins zwei..."

local Sender = neuropil:new{}
Sender:authorize(function () return true end)
-- XXX: Needs explicit port, otherwise test fails.
Sender:listen("udp4", "localhost", 4343)
Sender:join(Controller:get_address())
Sender:send(test_subject, test_data)

local Receiver = neuropil:new{}
Receiver:authorize(function () return true end)
-- XXX: Needs explicit port, otherwise test fails.
Receiver:listen("udp4", "localhost", 4444)
-- XXX: segmentation fault if receive is called before listen
Receiver:receive(test_subject, function (message)
   assert(ffi.string(message.data, message.data_length) == test_data)
   print("Received test data successfully.")
   os.exit(0)
end)
Receiver:join(Controller:get_address())

local deadline = os.time() + 120
while true do
   -- XXX: test fails if running for .1 seconds instead of 1 second each
   Controller:run(1)
   Sender:run(1)
   Receiver:run(1)
   assert(os.time() < deadline, "Test failed (timeout)")
end
