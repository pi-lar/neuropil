from _neuropil import lib, ffi

class Neuropil:

    __callback_info_dict__ = {}
    
    def __init__(self):
        self._settings = lib.np_default_settings(ffi.NULL)
        # self._settings.log_level = 0xfffd
        self._settings.log_file = b'./neuropil.log'
        self._settings.n_threads = 3
        self._context  = lib.np_new_context(self._settings)
    
    def __del__(self):
        # lib.np_destroy(self._context)
        pass

    def set_authn_cb(self, authn_callback):
        key = '{type}:{func_name}'.format(type="authn", func_name=str(authn_callback))
        if key in self.__callback_info_dict__:
            del self.__callback_info_dict__[key]
        self.__callback_info_dict__[key] = authn_callback
        return lib.np_set_authenticate_cb(self._context, authn_callback)

    def set_authz_cb(self, authz_callback):
        key = '{type}:{func_name}'.format(type="authz", func_name=str(authz_callback))
        if key in self.__callback_info_dict__:
            del self.__callback_info_dict__[key]
        self.__callback_info_dict__[key] = authz_callback
        return lib.np_set_authorize_cb(self._context, authz_callback)

    def set_accounting_cb(self, authz_callback):
        key = '{type}:{func_name}'.format(type="acct", func_name=str(authz_callback))
        if key in self.__callback_info_dict__:
            del self.__callback_info_dict__[key]
        self.__callback_info_dict__[key] = authz_callback
        return lib.np_set_accounting_cb(self._context, authz_callback)

    def set_receive_cb(self, subject, recv_callback):
        key = '{type}:{subject}:{func_name}'.format(type="recv", subject=subject, func_name=str(recv_callback))
        if key in self.__callback_info_dict__:
            self.__callback_info_dict__[key].append(recv_callback)
        else:
            self.__callback_info_dict__[key] = []
            self.__callback_info_dict__[key].append(recv_callback)
        return lib.np_add_receive_cb(self._context, subject, recv_callback)

    def listen(self, protocol, hostname, port):
        return lib.np_listen(self._context, protocol, hostname, port)

    def join(self, connect_string):
        return lib.np_join(self._context, connect_string)
            
    def run(self, interval):
        result = lib.np_run(self._context, interval)
        if result is not lib.np_ok:
            print('{error}'.format(error=ffi.string(lib.np_error_str[result])) )
        return result

    def send(self, subject, message):
        raw_bytes = ffi.from_buffer(message)
        print ("{length_m}:{length_r}".format(length_m=len(message), length_r=len(raw_bytes) ) )
        return lib.np_send(self._context, subject, raw_bytes, len(raw_bytes));

    def send_to(self, subject, message, target):
        raw_bytes = ffi.from_buffer(message)
        return lib.np_send_to(self._context, subject, raw_bytes, len(raw_bytes), target);

    def new_identity(self, expires_at, secret_key):
        return lib.np_new_identity(self._context, expires_at, secret_key);
    def use_identity(self, identity):
        return lib.np_use_identity(self._context, identity);

    def get_mx_properties(self, subject):    
        return lib.np_get_mx_properties(self._context, subject);    
    def set_mx_properties(self, mx_properties):
        return lib.np_set_mx_properties(self._context, subject, properties);
	    
    def set_userdata(self, userdata):
        lib.np_set_userdata(self._context, userdata);
    def get_userdata(self):
        return lib.np_get_userdata(self._context);
    
    def has_joined(self):
        return lib.np_has_joined(self._context);		
    def get_status(self):
        return lib.np_get_status(self._context);
