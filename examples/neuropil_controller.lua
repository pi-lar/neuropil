--
-- SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
-- SPDX-License-Identifier: OSL-3.0
--

local neuropil = require("neuropil")

local Controller = neuropil:new{}

Controller:authenticate(function (id)
   -- TODO: Make sure that id.public_key is an authenticated peer!
   print(("Joined: %02X%02X%02X%02X%02X%02X%02X..."):format(
         id.public_key[0], id.public_key[1], id.public_key[2],
         id.public_key[3], id.public_key[4], id.public_key[5],
         id.public_key[6]))
   return true
end)

Controller:listen("udp4", "localhost", 2345)

print("Bootstrap address: "..Controller:get_address())

while true do
   Controller:run(5)
end
