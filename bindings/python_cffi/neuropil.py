
from _neuropil import lib as neuropil, ffi
import time, copy, inspect

class NeuropilException(Exception):
    def __init__(self, message, error):
        super().__init__(message)
        self.error = error

class np_mx_properties(object):

    def __init__(self, raw, **entries):
        self._ignore_at_conversion = ["subject","_raw"]
        self.subject = None
        self._raw = raw
        self.__dict__.update(entries)

    def apply(self):
        return self.set_mx_properties()

    def set_mx_properties(self):
        ret = neuropil.np_invalid_argument
        if self._raw and self.subject:
            ret = self._raw.set_mx_properties(self.subject, self)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)

        return ret

    # enum np_data_return np_set_mxp_attr_bin(np_context *ac,   char * subject,         enum np_msg_attr_type  inheritance, char key[255], unsigned char * bin, size_t bin_length);
    def set_attr_bin(self, key:bytes, data:bytes):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(data, str):
            data = data.encode("utf-8")
        data_return = neuropil.np_set_mxp_attr_bin(self._raw._context, self.subject, neuropil.NP_ATTR_NONE, key, data, len(data))

        if data_return != neuropil.np_data_ok:
            raise NeuropilException(f'Could not set attribute. Error code: {data_return}. Please review neuropil_data.h for details',data_return)

class np_id(object):

    def __init__(self, id_cdata):
        self._cdata = id_cdata
        s = ffi.new("char[65]", b'\0')
        neuropil.np_id_str(s, self._cdata)
        self._hex = ffi.string(s).decode("utf-8")

    def __str__(self):
        return self._hex


class np_token(object):
    def __init__(self, node, raw,  **entries):
        self._ignore_at_conversion = ["_raw","_node"]
        self._raw = raw
        self._node = node
        self.__dict__.update(entries)

    def get_fingerprint(self, check_attributes:bool=False):
        id = ffi.new("np_id", b'\0')
        ret = neuropil.np_token_fingerprint(self._node._context, _NeuropilHelper.convert_from_python(self), check_attributes, ffi.addressof(id))

        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)

        return np_id(id)

    def get_attr_bin(self, key:bytes):
        if isinstance(key, str):
            key = key.encode("utf-8")
        out_data_config = ffi.new("struct np_data_conf[1]")
        out_data_config_ptr = ffi.new("struct np_data_conf *[1]")
        out_data_config_ptr[0] = ffi.addressof(out_data_config[0])
        out_data = ffi.new("unsigned char *[1]")
        out_data[0] = ffi.NULL

        data_return = neuropil.np_get_token_attr_bin(ffi.addressof(self._raw), key, out_data_config_ptr, out_data)

        data = None
        if data_return == neuropil.np_data_ok:
            data = bytearray(out_data_config[0].data_size)
            ffi.memmove(data, out_data[0], out_data_config[0].data_size)
        else:
            raise NeuropilException(f'Could not receive attribute \"{str(key)}\". Error code: {data_return}. Please review neuropil_data.h for details',data_return)

        return data

    #enum np_data_return np_set_ident_attr_bin(np_context *ac, struct np_token* ident, enum np_msg_attr_type  inheritance, char key[255], unsigned char * bin, size_t bin_length);
    def set_attr_bin(self, key:bytes, data:bytes):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(data, str):
            data = data.encode("utf-8")
        data_return = neuropil.np_set_ident_attr_bin(self._node._context, ffi.addressof(self._raw), neuropil.NP_ATTR_NONE, key, data, len(data))

        if data_return != neuropil.np_data_ok:
            raise NeuropilException(f'Could not set attribute. Error code: {data_return}. Please review neuropil_data.h for details',data_return)

class np_message(object):
    def __init__(self, _data, _raw, **entries):
        self.data_length = 0
        self.__dict__.update(entries)
        self._raw = _raw
        self._data = bytes(ffi.buffer(_data['data'], self.data_length))

    def raw(self):
        return self._data

    #enum np_data_return np_get_msg_attr_bin(struct np_message * msg, char key[255], struct np_data_conf ** out_data_config, unsigned char ** out_data);
    def get_attr_bin(self, key:bytes):
        if isinstance(key, str):
            key = key.encode("utf-8")
        out_data_config = ffi.new("struct np_data_conf[1]")
        out_data_config_ptr = ffi.new("struct np_data_conf *[1]")
        out_data_config_ptr[0] = ffi.addressof(out_data_config[0])
        out_data = ffi.new("unsigned char *[1]")
        out_data[0] = ffi.NULL

        data_return = neuropil.np_get_msg_attr_bin(ffi.addressof(self._raw), key, out_data_config_ptr, out_data)

        data = None
        if data_return == neuropil.np_data_ok:
            data = bytearray(out_data_config[0].data_size)
            ffi.memmove(data, out_data[0], out_data_config[0].data_size)
        else:
            raise NeuropilException(f'Could not receive attribute \"{key}\". Error code: {data_return}. Please review neuropil_data.h for details',data_return)

        return data



class NeuropilCluster(object):

    def __init__(self, count, port_range = 3000, host = b'localhost', proto= b'udp4', auto_run=True, log_file_prefix="", **settings):
        self.nodes = []

        if count <= 0:
            raise ValueError("The `count` of a cluster needs to be greater than 0")

        if not isinstance(port_range, list):
            port_range = range(port_range, port_range+count)
        if not isinstance(proto, list):
            proto = [proto]*count

        for c in range(0,count):
            port=port_range[c]
            log_file = f"{log_file_prefix}{host}_{port}.log"
            node = NeuropilNode(port=port,host=host,proto=proto[c],auto_run=auto_run,log_file=log_file,**settings)
            self.nodes.append(node)

    def __getattr__ (self, name):
        if self.nodes:
            first_attr = object.__getattribute__(self.nodes[0], name)
            if hasattr(first_attr, '__call__'):
                def wrapper_fn(*args, **kwargs):
                    ret = []
                    for node in self.nodes:
                        attr = object.__getattribute__(node, name)
                        ret.append((node, attr(*args, **kwargs)))
                    return ret
                return wrapper_fn
            else:
                return first_attr
        raise AttributeError(f'{self.__class__.__name__}.{name} is invalid.')

class NeuropilNode(object):

    def __init__(self, port, host = b'localhost', proto= b'udp4', auto_run=True, **settings):
        # DEFAULTS START
        # ffi interaction variables
        self._ffi_handle = None
        self._settings = None
        self._context = None
        # python class variables
        self._host = host
        self._proto = proto
        self._port = port
        self._userdata = None
        self._destroyed = False
        # default aaa callbacks
        self._user_authn_cb = lambda s,x: False # Default return False
        self._user_authz_cb = lambda s,x: False # Default return False
        self._user_accou_cb = lambda s,x: False # Default return False
        # user subject callbacks
        self.__callback_info_dict__ = {}
        # DEFAULTS END

        self._ffi_handle = ffi.new_handle(self)
        self._settings = neuropil.np_default_settings(ffi.NULL)
        setting_type=ffi.typeof(self._settings[0])
        for key, cdata in setting_type.fields:
            if key in settings:
                setattr(self._settings, key, _NeuropilHelper.convert_from_python( settings[key]))

        self._context = neuropil.np_new_context(self._settings)
        neuropil.np_set_userdata(self._context, self._ffi_handle)

        self.listen(self._proto, self._host, self._port)
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

    def get_fingerprint(self):
        id = ffi.new("np_id", b'\0')
        ret = neuropil.np_node_fingerprint(self._context, ffi.addressof(id))

        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)

        return np_id(id)

    def set_receive_cb(self, subject:bytes, recv_callback):
        if isinstance( subject, str):
             subject =  subject.encode("utf-8")

        if not isinstance( subject, bytes):
            raise ValueError(f"Subject needs to be of type `bytes` or `str`")

        ret = neuropil.np_ok

        subject_npid = ffi.new("np_id")
        subject_id = ffi.new("char[65]",b'\0')
        neuropil.np_get_id(ffi.addressof(subject_npid), subject, 64)
        neuropil.np_id_str(subject_id, subject_npid)
        subject_id = _NeuropilHelper.convert_to_python(self, subject_id)

        if subject_id not in self.__callback_info_dict__:
            self.__callback_info_dict__[subject_id] = []
            ret = neuropil.np_add_receive_cb(self._context, subject, neuropil._py_subject_callback)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)
        else:
            self.__callback_info_dict__[subject_id].append(recv_callback)
        return ret

    def listen(self, protocol:str, hostname:str, port:int):
        protocol = _NeuropilHelper.convert_from_python(protocol)
        hostname = _NeuropilHelper.convert_from_python(hostname)
        port     = _NeuropilHelper.convert_from_python(port)

        if not isinstance( protocol, bytes):
            raise ValueError(f"protocol needs to be of type `bytes` or `str`")
        if not isinstance( hostname, bytes):
            raise ValueError(f"hostname needs to be of type `bytes` or `str`")
        if not isinstance( port, int):
            raise ValueError(f"port needs to be of type `int`")

        ret = neuropil.np_listen(self._context, protocol, hostname, port)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)
        return ret

    def join(self, connect_string:str):
        if isinstance(connect_string, str):
            connect_string = connect_string.encode("utf-8")
        if not isinstance(connect_string, bytes):
            raise ValueError(f"connect_string needs to be of type `bytes` or `str`")

        ret = neuropil.np_join(self._context, connect_string)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)
        return ret

    def run(self, interval:float):
        if not isinstance(interval, float):
            interval = float(interval)
        ret = neuropil.np_run(self._context, interval)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)
        return ret

    def send(self, subject:str, message:bytes):
        if isinstance(subject, str):
            subject = subject.encode("utf-8")
        if isinstance(message, str):
            message = message.encode("utf-8")
        if not isinstance(subject, bytes):
            raise ValueError(f"subject needs to be of type `bytes` or `str`")

        raw_bytes = ffi.from_buffer(message)
        ret = neuropil.np_send(self._context, subject, raw_bytes, len(raw_bytes))
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)
        return ret

    def new_identity(self, expires_at:float=time.time()+(60*60*24), secret_key:bytes=None):
        if not isinstance(expires_at, float):
            raise ValueError(f"expires_at needs to be of type `float`")
        if not isinstance(secret_key, bytes) and secret_key != None:
            raise ValueError(f"secret_key needs to be of type `bytes` or `None`")
        if secret_key == None:
            secret_key = ffi.NULL

        ffi_token = neuropil.np_new_identity(self._context, expires_at, secret_key)
        ret = _NeuropilHelper.convert_to_python(self, ffi_token)
        return ret

    def use_identity(self, identity:np_token):
        if not isinstance(identity, np_token):
            raise ValueError(f"identity needs to be of type `np_token`")

        token_dict =  _NeuropilHelper.convert_from_python(identity)
        #ffi_token = ffi.new("struct np_token", token_dict)

        ret = neuropil.np_use_identity(self._context, identity._raw)

        if ret is not neuropil.np_ok:
            raise NeuropilException('Could not use identity. Error: {error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)
        return ret

    def get_mx_properties(self, subject:bytes):
        if isinstance(subject, str):
            subject = subject.encode("utf-8")
        if not isinstance(subject, bytes):
            raise ValueError(f"subject needs to be of type `bytes` or `str`")

        ret = neuropil.np_get_mx_properties(self._context, subject)

        if ret == ffi.NULL:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)
        else:
            ret = _NeuropilHelper.convert_to_python(self, ret)
            ret.subject = subject # currently no native part of the np_mx_property

        return ret

    def set_mx_properties(self, subject:bytes, mx_property:np_mx_properties):
        subject = _NeuropilHelper.convert_from_python(subject)

        if not isinstance(subject, bytes):
            raise ValueError(f"subject needs to be of type `bytes` or `str`")
        if not isinstance(mx_property, np_mx_properties):
            raise ValueError(f"mx_property needs to be of type `np_mx_properties`")

        ret = neuropil.np_set_mx_properties(self._context, subject, _NeuropilHelper.convert_from_python(mx_property))

        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)

        return ret

    def set_userdata(self, userdata):
        self._userdata.data = userdata
    def get_userdata(self):
        return self._userdata.data

    def has_joined(self):
        return neuropil.np_has_joined(self._context)

    def np_has_receiver_for(self, subject:str):
        subject = _NeuropilHelper.convert_from_python(subject)

        if not isinstance(subject, bytes):
            raise ValueError(f"subject needs to be of type `bytes` or `str`")

        return neuropil.np_has_receiver_for(self._context, subject)

    def get_address(self):
        address = ffi.new("char[500]",b'\0')
        status = neuropil.np_get_address(self._context, address, 255)
        #no optional exception throwing due to the fact that the return is not the fn status
        if status is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(status))),status)

        return ffi.string(address).decode("utf-8")

    def get_status(self):
        ret = neuropil.np_get_status(self._context)
        return ret

    def set_attr_bin(self, key:bytes, data:bytes, inheritance=neuropil.NP_ATTR_IDENTITY):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(data, str):
            data = data.encode("utf-8")
        data_return = neuropil.np_set_ident_attr_bin(self._context, ffi.NULL, inheritance, key, data, len(data))

        if data_return != neuropil.np_data_ok:
            raise NeuropilException(f'Could not set attribute. Error code: {data_return}. Please review neuropil_data.h for details',data_return)

    def set_authenticate_cb(self, authn_callback):
        self._user_authn_cb = authn_callback
        ret =  neuropil.np_set_authenticate_cb(self._context, neuropil._py_authn_cb)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)
        return ret

    def set_authorize_cb(self, authz_callback):
        self._user_authz_cb = authz_callback
        ret = neuropil.np_set_authorize_cb(self._context, neuropil._py_authz_cb)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)
        return ret

    def set_accounting_cb(self, acc_callback):
        self._user_accou_cb = acc_callback
        ret = neuropil.np_set_accounting_cb(self._context, neuropil._py_acc_cb)
        if ret is not neuropil.np_ok:
            raise NeuropilException('{error}'.format(error=ffi.string(neuropil.np_error_str(ret))),ret)
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
                if field == "data" :
                    yield (field,getattr( s, field ))
                else:
                    yield (field, _NeuropilHelper.convert_to_python(node,  getattr( s, field )))

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
                ret = np_message(ret, s, **ret)
            elif  type.cname == 'struct np_token':
                ret = np_token(node, s, **ret)
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
    def __convert_from_python(s:dict, ignore_attr=[]):
        ret = {}
        for key, value in s.items():
            if key not in ignore_attr:
                ret[key] = _NeuropilHelper.__convert_value_from_python(value)
        return ret

    @staticmethod
    def convert_from_python(s):
        ignore_attr=[]
        if hasattr(s,"_ignore_at_conversion"):
            ignore_attr = s._ignore_at_conversion+["_ignore_at_conversion"]

        if isinstance(s, dict):
            return _NeuropilHelper.__convert_from_python(s, ignore_attr)
        elif hasattr(s, '__dict__'):
            return _NeuropilHelper.__convert_from_python(s.__dict__, ignore_attr)
        else:
            return _NeuropilHelper.__convert_value_from_python(s)

@ffi.def_extern()
def _py_subject_callback(context, message):
    ret = True
    myself = _NeuropilHelper.from_context(context)
    msg = _NeuropilHelper.convert_to_python(myself, message)

    subject_id = ffi.new("char[65]",b'\0')
    neuropil.np_id_str(subject_id, msg.subject)
    subject_id = _NeuropilHelper.convert_to_python(myself, subject_id)
    if myself.__callback_info_dict__[subject_id]:
        for user_fn in myself.__callback_info_dict__[subject_id]:
            if len(inspect.signature(user_fn).parameters) == 2:
                ret = bool(user_fn(myself, msg)) and ret
            else:
                ret = bool(user_fn(msg)) and ret
    return ret

@ffi.def_extern()
def _py_authn_cb(context, token):
    myself = _NeuropilHelper.from_context(context)
    return bool(myself._user_authn_cb(myself, _NeuropilHelper.convert_to_python(myself, token)))

@ffi.def_extern()
def _py_authz_cb(context, token):
    myself = _NeuropilHelper.from_context(context)
    return bool(myself._user_authz_cb(myself, _NeuropilHelper.convert_to_python(myself, token)))

@ffi.def_extern()
def _py_acc_cb(context, token):
    myself = _NeuropilHelper.from_context(context)
    return bool(myself._user_accou_cb(myself, _NeuropilHelper.convert_to_python(myself, token)))
