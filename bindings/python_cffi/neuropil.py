
from _neuropil import lib as neuropil, ffi
import time, copy

class NeuropilException(Exception):
    def __init__(self, message, error):        
        super().__init__(message)
        self.error = error

class np_mx_properties(object):
    subject = None
    parent = None

    def __init__(self, parent, **entries):
        self.parent = parent
        self.__dict__.update(entries)

    def apply(self):
        return self.set_mx_properties()

    def set_mx_properties(self):
        ret = neuropil.np_invalid_argument
        if self.parent and self.subject:
            ret = self.parent.set_mx_properties(self.subject, self)

        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)

        return ret

class np_token(object):
    def __init__(self, **entries):
        self.__dict__.update(entries)

class np_message(object):
    data = None
    data_length = 0
    def __init__(self, **entries):
        self.__dict__.update(entries)
    
    def raw(self):
        return ffi.buffer(self.data,self.data_length)

class NeuropilCluster(object):    
    nodes = []
    def __init__(self, count, port_range = 3000, host = b'localhost', proto= b'udp4', auto_run=True, **settings):   
        if count <= 0:
            raise ValueError("The `count` of a Cluster needs to be be greater than 0")

        if not isinstance(port_range, list):
            port_range = range(port_range, port_range+count)
        if not isinstance(proto, list):
            proto = [proto]*count

        for c in range(0,count):
            node = NeuropilNode(port_range[c],host,proto[c],auto_run,**settings)
            self.nodes.append(node)        

    def __getattr__ (self, name):
        if self.nodes:            
            fistattr = object.__getattribute__(self.nodes[0], name)
            if hasattr(fistattr, '__call__'):
                def wrapper_fn(*args, **kwargs):
                    ret = []
                    for node in self.nodes:
                        attr = object.__getattribute__(node, name)
                        ret.append((node, attr(*args, **kwargs)))
                    return ret
                return wrapper_fn
            else:
                return fistattr
        raise AttributeError(f'{self.__class__.__name__}.{name} is invalid.')

class NeuropilNode(object):    

    # ffi interaction variables
    _ffi_handle = None
    _settings = None    
    _context = None   
    # python class variables
    _userdata = None
    _destroyed = False
    # default aaa callbacks
    _user_authn_cb = lambda s,x: True # Default return True 
    _user_authz_cb = lambda s,x: True # Default return True
    _user_accou_cb = lambda s,x: True # Default return True
    # user subject callbacks    
    __callback_info_dict__ = {}

    
    def __init__(self, port, host = b'localhost', proto= b'udp4', auto_run=True, **settings):        
        self._ffi_handle = ffi.new_handle(self)        
        self._settings = neuropil.np_default_settings(ffi.NULL)
        setting_type=ffi.typeof(self._settings[0])        
        for key, cdata in setting_type.fields:            
            if key in settings:                        
                setattr(self._settings, key, _NeuropilHelper.convert_from_python( settings[key]))

        self._context = neuropil.np_new_context(self._settings)        
        neuropil.np_set_userdata(self._context, self._ffi_handle)

        self.listen(proto, host, port)
        if auto_run:
            self.run(0)

    def __del__(self):
        if not self._destroyed:
            self._destroyed = True             
            neuropil.np_destroy(self._context, False)        

    def shutdown(self):         
        if not self._destroyed:
            self._destroyed = True
            neuropil.np_destroy(self._context, True)
        

    @staticmethod
    @ffi.callback("bool(np_context* context, struct np_message*)")
    def _py_subject_callback(context, message):        
        ret = True
        myself = _NeuropilHelper.from_context(context)                
        if myself.__callback_info_dict__[message.subject]:
            msg = _NeuropilHelper.convert_to_python(myself, message)
            for user_fn in myself.__callback_info_dict__[message.subject]:
                ret = bool(user_fn(myself, msg)) and ret
        return ret

    def set_receive_cb(self, subject:str, recv_callback):
        if isinstance( subject, str):
             subject =  subject.encode("utf-8")

        if not isinstance( subject, bytes):             
            raise ValueError(f"Subject needs to be `bytes` or `str`")

        ret = neuropil.np_ok
        if subject not in self.__callback_info_dict__:            
            self.__callback_info_dict__[subject] = []
            ret = neuropil.np_add_receive_cb(self._context, subject, NeuropilNode._py_subject_callback)            
        self.__callback_info_dict__[subject].append(recv_callback)                    
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
        return ret

    def listen(self, protocol:str, hostname:str, port:int):
        if isinstance(protocol, str):
            protocol = protocol.encode("utf-8")
        if isinstance(hostname, str):
            hostname = hostname.encode("utf-8")
        if not isinstance( protocol, bytes):             
            raise ValueError(f"protocol needs to be `bytes` or `str`")
        if not isinstance( hostname, bytes):             
            raise ValueError(f"hostname needs to be `bytes` or `str`")
        if not isinstance( port, int):             
            raise ValueError(f"port needs to be `int`")
        ret = neuropil.np_listen(self._context, protocol, hostname, port)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
        return ret

    def join(self, connect_string:str):
        if isinstance(connect_string, str):
            connect_string = connect_string.encode("utf-8")
        if not isinstance(connect_string, bytes):             
            raise ValueError(f"connect_string needs to be `bytes` or `str`")

        ret = neuropil.np_join(self._context, connect_string)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
        return ret
            
    def run(self, interval:float):
        if not isinstance(interval, float):             
            interval = float(interval)
        ret = neuropil.np_run(self._context, interval)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
        return ret

    def send(self, subject:str, message:bytes):
        if isinstance(subject, str):
            subject = subject.encode("utf-8")
        if not isinstance(subject, bytes):             
            raise ValueError(f"subject needs to be `bytes` or `str`")

        raw_bytes = ffi.from_buffer(message)        
        ret = neuropil.np_send(self._context, subject, raw_bytes, len(raw_bytes))
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
        return ret

    def new_identity(self, expires_at:float=time.time(), secret_key:bytes=None):
        if not isinstance(expires_at, float):             
            raise ValueError(f"expires_at needs to be `float`")
        if not isinstance(secret_key, bytes) and secret_key != None:
            raise ValueError(f"secret_key needs to be `bytes` or `None`")
        if secret_key == None:
            secret_key = ffi.NULL

        ret = neuropil.np_new_identity(self._context, expires_at, secret_key)        
        ret = _NeuropilHelper.convert_to_python(self, ret)
        return ret

    def use_identity(self, identity:np_token):
        if not isinstance(identity, np_token):             
            raise ValueError(f"identity needs to be `np_token`")

        token =  _NeuropilHelper.convert_from_python(identity)
        ret = neuropil.np_use_identity(self._context, token)

        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
        return ret

    def get_mx_properties(self, subject:str):    
        if isinstance(subject, str):
            subject = subject.encode("utf-8")
        if not isinstance(subject, bytes):             
            raise ValueError(f"subject needs to be `bytes` or `str`")

        ret = neuropil.np_get_mx_properties(self._context, subject)
        
        if ret == ffi.NULL:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
        else:
            ret = _NeuropilHelper.convert_to_python(self, ret)
            
        return ret

    def set_mx_properties(self, subject:str, mx_property:np_mx_properties):
        if isinstance(subject, str):
            subject = subject.encode("utf-8")
        if not isinstance(subject, bytes):             
            raise ValueError(f"subject needs to be `bytes` or `str`")
        if not isinstance(mx_property, np_mx_properties):             
            raise ValueError(f"mx_property needs to be `np_mx_properties`")
         
        ret = neuropil.np_set_mx_properties(self._context, subject, _NeuropilHelper.convert_from_python(mx_property))

        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
            
        return ret

    def set_userdata(self, userdata):
        self._userdata.data = userdata
    def get_userdata(self):
        return self._userdata.data
    
    def has_joined(self):
        return neuropil.np_has_joined(self._context)

    def get_address(self):
        address = ffi.new("char[255]")
        status = neuropil.np_get_address(self._context, address, 255)
        #no optional exception throwing due to the fact that the return is not the fn status
        if status is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[status])),status)

        return ffi.string(address).decode("utf-8")
    
    def get_status(self):
        ret = neuropil.np_get_status(self._context)     
        return ret
            
    @staticmethod
    @ffi.callback("bool(np_context* context, struct np_token*)")
    def _py_authn_cb(context, token):        
        myself = _NeuropilHelper.from_context(context)        
        return bool(myself._user_authn_cb(_NeuropilHelper.convert_to_python(myself, token)))

    @staticmethod
    @ffi.callback("bool(np_context* context, struct np_token*)")
    def _py_authz_cb(context, token):
        myself = _NeuropilHelper.from_context(context)        
        return bool(myself._user_authz_cb(_NeuropilHelper.convert_to_python(myself, token)))
        
    @staticmethod
    @ffi.callback("bool(np_context* context, struct np_token*)")
    def _py_acc_cb(context, token):
        myself = _NeuropilHelper.from_context(context)        
        return bool(myself._user_accou_cb(_NeuropilHelper.convert_to_python(myself, token)))        

    def set_authenticate_cb(self, authn_callback):        
        self._user_authn_cb = authn_callback        
        ret =  neuropil.np_set_authenticate_cb(self._context, NeuropilNode._py_authn_cb)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
        return ret

    def set_authorize_cb(self, authz_callback):
        self._user_authz_cb = authz_callback
        ret = neuropil.np_set_authorize_cb(self._context, NeuropilNode._py_authz_cb)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
        return ret

    def set_accounting_cb(self, acc_callback):
        self._user_accou_cb = acc_callback
        ret = neuropil.np_set_accounting_cb(self._context, NeuropilNode._py_acc_cb)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str[ret])),ret)
        return ret

class _NeuropilHelper():    
    @staticmethod
    def from_context(context):
        return ffi.from_handle(neuropil.np_get_userdata(context))

    @staticmethod
    def __convert_struct_field(node:NeuropilNode, s, fields ):
        for field,fieldtype in fields:
            if fieldtype.type.kind == 'primitive':
                yield (field,getattr( s, field ))
            else:
                yield (field, _NeuropilHelper.convert_to_python(node,  getattr( s, field ) ))
    @staticmethod
    def convert_to_python(node:NeuropilNode, s):
        ret = None        
        type = None
        try:
            type = ffi.typeof(s)
        except:
            ret = s

        if type == None:
            pass
        elif type.kind == 'struct':
            ret = dict(_NeuropilHelper.__convert_struct_field(node,  s, type.fields))            
            if type.cname == 'struct np_message':
                ret = np_message(**ret)
            elif  type.cname == 'struct np_token':
                ret = np_token(**ret)
            elif  type.cname == 'struct np_mx_properties':
                ret = np_mx_properties(node, **ret)                
        elif type.kind == 'array':
            if type.item.kind == 'primitive':
                if type.item.cname == 'char':
                    ret = ffi.string(s).decode("utf-8")
                else:
                    ret = [ s[i] for i in range(type.length) ]
            else:
                ret = [ _NeuropilHelper.convert_to_python(node, s[i]) for i in range(type.length) ]
        elif type.kind == 'primitive':
            ret = int(s)
        elif type.kind == 'pointer':            
                ret = _NeuropilHelper.convert_to_python(node, s[0])
        else:
            print(f"_NeuropilHelper.convert_to_python: _NeuropilHelper.convert_to_python: unknown {type.kind}")
    
        return ret

    @staticmethod
    def __convert_value_from_python(value):            
        ret = value
        if isinstance(value, str):
            ret = value.encode("utf-8")        
        return ret

    @staticmethod
    def __convert_from_python(s:dict):    
        ret = {}
        for key, value in s.items():
            ret[key] = _NeuropilHelper.__convert_value_from_python(value)
        return ret

    @staticmethod
    def convert_from_python(s):
        if isinstance(s, dict):
            return _NeuropilHelper.__convert_from_python(s)
        elif hasattr(s, '__dict__'):
            return _NeuropilHelper.__convert_from_python(s.__dict__)
        else:
            return _NeuropilHelper.__convert_value_from_python(s)

