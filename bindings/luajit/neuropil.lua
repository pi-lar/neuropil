--
-- SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
-- SPDX-License-Identifier: OSL-3.0
--

local ffi = require("ffi")
local neuropil = require("neuropil_ffi")

local Context = {}

function Context:new (settings)
   local cfg = ffi.new('struct np_settings')
   neuropil.np_default_settings(cfg)
   if settings.n_threads then
      cfg.n_threads = settings.n_threads
   end
   if settings.log_file then
      assert(#settings.log_file <= ffi.sizeof(cfg.log_file),
             "log_file path is too long.")
      ffi.copy(cfg.log_file, settings.log_file)
   end
   return setmetatable({ac=neuropil.np_new_context(cfg)}, {__index=Context})
end

local function np_assert (result)
   assert(neuropil.np_ok == result, neuropil.np_error_str(result))
end

function Context:listen (protocol, host, port)
   np_assert(neuropil.np_listen(self.ac, protocol, host, port or 0))
end

function Context:get_address ()
   local address = ffi.new("char[1000]")
   np_assert(neuropil.np_get_address(self.ac, address, ffi.sizeof(address)))
   return ffi.string(address)
end

function Context:join (address)
   np_assert(neuropil.np_join(self.ac, address))
end

function Context:send (subject, message, length)
   if not length then
      if     type(message) == 'string' then length = #message
      elseif type(message) == 'cdata'  then length = ffi.sizeof(message)
      else error("Invalid message type: "..type(message)) end
   end
   np_assert(neuropil.np_send(self.ac, subject, message, length))
end

function Context:receive (subject, callback)
   local function wrapped_callback (_, message)
      return callback(message[0])
   end
   np_assert(neuropil.np_add_receive_cb(self.ac, subject, wrapped_callback))
end

function Context:authorize (callback)
   local function wrapped_callback (_, token)
      return callback(token[0])
   end
   np_assert(neuropil.np_set_authorize_cb(self.ac, wrapped_callback))
end

function Context:authenticate (callback)
   local function wrapped_callback (_, token)
      return callback(token[0])
   end
   np_assert(neuropil.np_set_authenticate_cb(self.ac, wrapped_callback))
end

function Context:accounting (callback)
   local function wrapped_callback (_, token)
      return callback(token[0])
   end
   np_assert(neuropil.np_set_accounting_cb(self.ac, wrapped_callback))
end

function Context:run (duration)
   np_assert(neuropil.np_run(self.ac, duration))
end

return Context
