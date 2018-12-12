from _neuropil import lib as neuropil, ffi


class Neuropil(object):
    __callback_info_dict__ = {}
    _userdata = None
    _ffi_handle = None
    _settings = None    
    _context = None
    _destroyed = False

    def __init__(self):
        self._ffi_handle = ffi.new_handle(self)        
        self._settings = neuropil.np_default_settings(ffi.NULL)                
        
        self._settings.log_level = 0
        self._context = neuropil.np_new_context(self._settings)        
        neuropil.np_set_userdata(self._context, self._ffi_handle)
    
    def __del__(self):
        if not self._destroyed:
            self._destroyed = True             
            neuropil.np_destroy(self._context, False)

    def shutdown(self): 
        ret = neuropil.np_ok       
        if not self._destroyed:
            self._destroyed = True
            ret = neuropil.np_destroy(self._context, True)
        return ret

    def set_authn_cb(self, authn_callback):
        key = '{type}:{func_name}'.format(type="authn", func_name=str(authn_callback))
        if key in self.__callback_info_dict__:
            del self.__callback_info_dict__[key]
        self.__callback_info_dict__[key] = authn_callback
        return neuropil.np_set_authenticate_cb(self._context, authn_callback)

    def set_authz_cb(self, authz_callback):
        key = '{type}:{func_name}'.format(type="authz", func_name=str(authz_callback))
        if key in self.__callback_info_dict__:
            del self.__callback_info_dict__[key]
        self.__callback_info_dict__[key] = authz_callback
        return neuropil.np_set_authorize_cb(self._context, authz_callback)

    def set_accounting_cb(self, authz_callback):
        key = '{type}:{func_name}'.format(type="acct", func_name=str(authz_callback))
        if key in self.__callback_info_dict__:
            del self.__callback_info_dict__[key]
        self.__callback_info_dict__[key] = authz_callback
        return neuropil.np_set_accounting_cb(self._context, authz_callback)

    def set_receive_cb(self, subject, recv_callback):
        key = '{type}:{subject}:{func_name}'.format(type="recv", subject=subject, func_name=str(recv_callback))
        if key in self.__callback_info_dict__:
            self.__callback_info_dict__[key].append(recv_callback)
        else:
            self.__callback_info_dict__[key] = []
            self.__callback_info_dict__[key].append(recv_callback)
        return neuropil.np_add_receive_cb(self._context, subject, recv_callback)

    def listen(self, protocol, hostname, port):
        return neuropil.np_listen(self._context, protocol, hostname, port)

    def join(self, connect_string):
        return neuropil.np_join(self._context, connect_string)
            
    def run(self, interval):
        result = neuropil.np_run(self._context, interval)
        if result is not neuropil.np_ok:
            raise RuntimeError('{error}'.format(error=ffi.string(neuropil.np_error_str[result])))
        return result

    def send(self, subject, message):
        raw_bytes = ffi.from_buffer(message)        
        return neuropil.np_send(self._context, subject, ffi.cast("uint8_t*", raw_bytes), len(raw_bytes))

    def new_identity(self, expires_at, secret_key):
        return neuropil.np_new_identity(self._context, expires_at, secret_key)
    def use_identity(self, identity):
        return neuropil.np_use_identity(self._context, identity)

    def get_mx_properties(self, subject):    
        return neuropil.np_get_mx_properties(self._context, subject)
	    
    def set_userdata(self, userdata):
        self._userdata.data = userdata
    def get_userdata(self):
        return self._userdata.data
    
    def has_joined(self):
        return neuropil.np_has_joined(self._context);		
    def get_status(self):
        return neuropil.np_get_status(self._context);
    
    @staticmethod
    def from_context(context):
        return ffi.from_handle(neuropil.np_get_userdata(context))

