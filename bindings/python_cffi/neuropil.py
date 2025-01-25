# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0
from _neuropil import lib as neuropil, ffi
from datetime import datetime, timezone
from typing import Union
import time, copy, inspect


class NeuropilException(Exception):
    def __init__(self, message, error):
        super().__init__(message)
        self.error = error


class np_mx_properties(object):
    def __init__(self, raw, **entries):
        self._ignore_at_conversion = ["subject", "_raw"]
        self.subject: np_subject = None
        self._raw = raw
        self.__dict__.update(entries)

    def apply(self):
        return self.set_mx_properties()

    def set_mx_properties(self):
        ret = neuropil.np_invalid_argument
        if self._raw and self.subject:
            ret = self._raw.set_mx_properties(self.subject, self)
        if ret != neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )

        return ret

    def set_attr_policy_bin(self, key: bytes, data: bytes):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(data, str):
            data = data.encode("utf-8")
        data_return = neuropil.np_set_mxp_attr_policy_bin(
            self._raw._context, self.subject._cdata, key, data, len(data)
        )

        if data_return != neuropil.np_data_ok:
            raise NeuropilException(
                f"Could not set attribute. Error code: {data_return}. Please review neuropil_data.h for details",
                data_return,
            )

    # enum np_data_return np_set_mxp_attr_bin(np_context *ac,   char * subject,         enum np_msg_attr_type  inheritance, char key[255], unsigned char * bin, size_t bin_length);
    def set_attr_bin(self, key: bytes, data: bytes):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(data, str):
            data = data.encode("utf-8")
        data_return = neuropil.np_set_mxp_attr_bin(
            self._raw._context,
            self.subject._cdata,
            neuropil.NP_ATTR_NONE,
            key,
            data,
            len(data),
        )

        if data_return != neuropil.np_data_ok:
            raise NeuropilException(
                f"Could not set attribute. Error code: {data_return}. Please review neuropil_data.h for details",
                data_return,
            )


class np_id(object):
    def __init__(self, id_cdata):
        self._cdata = id_cdata
        self._update_hex()

    def _update_hex(self, size=65):
        s = ffi.new(f"char[{size}]", b"\0")
        neuropil.np_id_str(s, self._cdata)
        self._hex = ffi.string(s).decode("utf-8")

    @staticmethod
    def from_hex(s):
        npid = ffi.new("np_id")
        neuropil.np_str_id(ffi.addressof(npid), s.encode("utf-8"))
        return np_id(npid)

    def __str__(self):
        return self._hex


class np_log_entry(object):
    def __init__(self, node, _cdata, **entries):
        self._ignore_at_conversion = ["_node", "_cdata", "_s"]
        self._cdata = _cdata
        self._node = node
        self.__dict__.update(entries)
        self.timestamp_as_datetime: datetime = datetime.fromtimestamp(
            int(self.timestamp), tz=timezone.utc
        )

    def __str__(self):
        return self.string


class np_subject(np_id):
    def __init__(self, id_cdata):
        super().__init__(id_cdata)

    def add(self, subject: str) -> int:
        np_subject.generate(subject, base_subject=self)
        self._update_hex()

    @staticmethod
    def generate(
        subject: Union[str, bytes], base_subject: "np_subject" = None
    ) -> "np_subject":
        _subject = subject
        if isinstance(_subject, str):
            _subject = _subject.encode("utf-8")
        if not isinstance(_subject, bytes):
            raise ValueError(
                f"argument `subject` needs to be of type `bytes` or `str`, not `{type(subject)}`"
            )

        if base_subject == None:
            id = ffi.new("np_subject", b"\0")
        else:
            id = base_subject._cdata
        code = neuropil.np_generate_subject(ffi.addressof(id), _subject, len(_subject))
        if code != neuropil.np_ok:
            raise NeuropilException(
                f'Could not generate subject "{str(subject)}". Error code: {code}. Please review neuropil.h for details',
                code,
            )

        return base_subject or np_subject(id)


class np_token(object):
    def __init__(self, node, raw, **entries):
        self._ignore_at_conversion = ["_raw", "_node"]
        self._raw = raw
        self._node = node
        self.__dict__.update(entries)

    def get_fingerprint(self, check_attributes: bool = False):
        id = ffi.new("np_id", b"\0")
        ret = neuropil.np_token_fingerprint(
            self._node._context,
            _NeuropilHelper.convert_from_python(self),
            check_attributes,
            ffi.addressof(id),
        )

        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )

        return np_id(id)

    def __getattribute__(self, name: str):
        match (name):
            case "issuer" | "audience" | "realm":
                return np_id(ffi.addressof(self._raw, name)[0])
            case _:
                return super().__getattribute__(name)

    def __setattr__(self, name: str, value) -> None:
        match (name):
            case "issuer" | "audience" | "realm":
                ffi.memmove(
                    ffi.addressof(self._raw, name),
                    ffi.addressof(value._cdata),
                    neuropil.NP_FINGERPRINT_BYTES,
                )
            case "public_key" | "secret_key" | "signature" | "attributes_signature":
                raise NeuropilException("operation not allowed")
            case _:
                super().__setattr__(name, value)

    def get_attr_bin(self, key: bytes):
        if isinstance(key, str):
            local_key = key.encode("utf-8")
        elif isinstance(key, np_id):
            local_key = str(key).encode("utf-8")
        else:
            local_key = key
        out_data_config = ffi.new("struct np_data_conf[1]")
        out_data_config_ptr = ffi.new("struct np_data_conf *[1]")
        out_data_config_ptr[0] = ffi.addressof(out_data_config[0])
        out_data = ffi.new("unsigned char *[1]")
        out_data[0] = ffi.NULL

        data_return = neuropil.np_get_token_attr_bin(
            ffi.addressof(self._raw), local_key, out_data_config_ptr, out_data
        )

        data = None
        if data_return == neuropil.np_data_ok:
            data = bytearray(out_data_config[0].data_size)
            ffi.memmove(data, out_data[0], out_data_config[0].data_size)
        else:
            raise NeuropilException(
                f'Could not receive attribute "{str(key)}". Error code: {data_return}. Please review neuropil_data.h for details',
                data_return,
            )

        return data

    # enum np_data_return np_set_ident_attr_bin(np_context *ac, struct np_token* ident, enum np_msg_attr_type  inheritance, char key[255], unsigned char * bin, size_t bin_length);
    def set_attr_bin(self, key: bytes, data: bytes):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(data, str):
            data = data.encode("utf-8")
        data_return = neuropil.np_set_ident_attr_bin(
            self._node._context,
            ffi.addressof(self._raw),
            neuropil.NP_ATTR_NONE,
            key,
            data,
            len(data),
        )

        if data_return != neuropil.np_data_ok:
            raise NeuropilException(
                f"Could not set attribute. Error code: {data_return}. Please review neuropil_data.h for details",
                data_return,
            )

    def sign_identity(self, token):
        ret = neuropil.np_sign_identity(
            self._node._context, ffi.addressof(token._raw), False
        )
        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        return ret

    def verify_issuer(self, issuer):
        ret = neuropil.np_verify_issuer(self._node._context, self._raw, issuer._raw)
        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        return ret

    def update(self):
        ret = neuropil.np_sign_identity(
            self._node._context, ffi.addressof(self._raw), True
        )
        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        return ret


class np_message(object):
    def __init__(self, _data, _raw, **entries):
        self.data_length = 0
        self.__dict__.update(entries)
        setattr(self, "from", np_id(getattr(self, "from")))
        self._raw = _raw
        self._data = bytes(ffi.buffer(_data["data"], self.data_length))
        self.subject = np_subject(self.subject)

    def raw(self):
        return self._data

    # enum np_data_return np_get_msg_attr_bin(struct np_message * msg, char key[255], struct np_data_conf ** out_data_config, unsigned char ** out_data);
    def get_attr_bin(self, key: bytes):
        if isinstance(key, str):
            key = key.encode("utf-8")
        out_data_config = ffi.new("struct np_data_conf[1]")
        out_data_config_ptr = ffi.new("struct np_data_conf *[1]")
        out_data_config_ptr[0] = ffi.addressof(out_data_config[0])
        out_data = ffi.new("unsigned char *[1]")
        out_data[0] = ffi.NULL

        data_return = neuropil.np_get_msg_attr_bin(
            ffi.addressof(self._raw), key, out_data_config_ptr, out_data
        )

        data = None
        if data_return == neuropil.np_data_ok:
            data = bytearray(out_data_config[0].data_size)
            ffi.memmove(data, out_data[0], out_data_config[0].data_size)
        else:
            raise NeuropilException(
                f'Could not receive attribute "{key}". Error code: {data_return}. Please review neuropil_data.h for details',
                data_return,
            )

        return data


class np_searchentry(object):
    def __init__(self, _raw, **entries):
        self._ignore_at_conversion = ["_raw"]
        self._raw = _raw
        self.__dict__.update(entries)


class np_searchquery(object):
    def __init__(self, _raw, **entries):
        self._ignore_at_conversion = ["_raw"]
        self._raw = _raw
        self.__dict__.update(entries)


class np_searchresult(object):
    def __init__(self, _raw, **entries):
        self._ignore_at_conversion = ["_raw"]
        self._raw = _raw
        self.__dict__.update(entries)


class NeuropilCluster(object):
    def __init__(
        self,
        count,
        port_range=3000,
        host="localhost",
        proto=b"udp4",
        auto_run=True,
        log_file_prefix="",
        custom_node_class=None,
        **settings,
    ):
        self.nodes = []

        if not custom_node_class:
            custom_node_class = NeuropilNode

        if count <= 0:
            raise ValueError("The `count` of a cluster needs to be greater than 0")

        if not isinstance(port_range, list):
            port_range = range(port_range, port_range + count)
        if not isinstance(proto, list):
            proto = [proto] * count

        for c in range(0, count):
            port = port_range[c]
            log_file = f"{log_file_prefix}{host}_{port}.log"
            node = custom_node_class(
                port=port,
                host=host,
                proto=proto[c],
                auto_run=auto_run,
                log_file=log_file,
                **settings,
            )
            self.nodes.append(node)

    def __getattr__(self, name):
        if self.nodes:
            first_attr = object.__getattribute__(self.nodes[0], name)
            if hasattr(first_attr, "__call__"):

                def wrapper_fn(*args, **kwargs):
                    ret = []
                    for node in self.nodes:
                        attr = object.__getattribute__(node, name)
                        ret.append((node, attr(*args, **kwargs)))
                    return ret

                return wrapper_fn
            else:
                return first_attr
        raise AttributeError(f"{self.__class__.__name__}.{name} is invalid.")


class NeuropilNode(object):
    def __init__(
        self,
        port,
        host=b"localhost",
        proto=b"udp4",
        auto_run=True,
        log_write_fn=None,
        **settings,
    ):
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
        self._user_authn_cb = lambda s, x: False  # Default return False
        self._user_authz_cb = lambda s, x: False  # Default return False
        self._user_accou_cb = lambda s, x: False  # Default return False
        # user subject callbacks
        self.__callback_info_dict__ = {}
        # DEFAULTS END

        self._ffi_handle = ffi.new_handle(self)
        self._settings = neuropil.np_default_settings(ffi.NULL)
        if log_write_fn:
            self._user_log_write_cb = log_write_fn
            self._settings.log_write_fn = neuropil._py_log_write_cb

        setting_type = ffi.typeof(self._settings[0])
        for key, cdata in setting_type.fields:
            if key in settings:
                setattr(
                    self._settings,
                    key,
                    _NeuropilHelper.convert_from_python(settings[key]),
                )

        self._context = neuropil.np_new_context(self._settings)
        neuropil.np_set_userdata(self._context, self._ffi_handle)

        self.listen(self._proto, self._host, self._port)
        if auto_run:
            self.run(0)

    def __del__(self):
        if not self._destroyed:
            self.shutdown(False)

    def shutdown(self, grace=True):
        if not self._destroyed:
            self._destroyed = True
            neuropil.np_destroy(self._context, grace)

    def get_fingerprint(self):
        id = ffi.new("np_id", b"\0")
        ret = neuropil.np_node_fingerprint(self._context, ffi.addressof(id))

        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )

        return np_id(id)

    def set_receive_cb(self, subject: Union[str, bytes, np_subject], recv_callback):
        subject = _NeuropilHelper.check_subject(subject)

        ret = neuropil.np_ok

        subject_id = str(subject)

        if subject_id not in self.__callback_info_dict__:
            self.__callback_info_dict__[subject_id] = []
            ret = neuropil.np_add_receive_cb(
                self._context, subject._cdata, neuropil._py_subject_callback
            )

        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        else:
            self.__callback_info_dict__[subject_id].append(recv_callback)
        return ret

    def listen(self, protocol: str, hostname: str, port: int):
        protocol = _NeuropilHelper.convert_from_python(protocol)
        hostname = _NeuropilHelper.convert_from_python(hostname)
        port = _NeuropilHelper.convert_from_python(port)

        if not isinstance(protocol, bytes):
            raise ValueError(f"protocol needs to be of type `bytes` or `str`")
        if not isinstance(hostname, bytes):
            raise ValueError(f"hostname needs to be of type `bytes` or `str`")
        if not isinstance(port, int):
            raise ValueError(f"port needs to be of type `int`")

        ret = neuropil.np_listen(self._context, protocol, hostname, port)
        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        return ret

    def join(self, connect_string: str):
        if isinstance(connect_string, str):
            connect_string = connect_string.encode("utf-8")
        if not isinstance(connect_string, bytes):
            raise ValueError(f"connect_string needs to be of type `bytes` or `str`")

        ret = neuropil.np_join(self._context, connect_string)
        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        return ret

    def run(self, interval: float):
        if not isinstance(interval, float):
            interval = float(interval)
        ret = neuropil.np_run(self._context, interval)
        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        return ret

    def send(self, subject: Union[str, bytes, np_subject], message: bytes):
        _subject = _NeuropilHelper.check_subject(subject)
        if isinstance(message, str):
            message = message.encode("utf-8")

        raw_bytes = ffi.from_buffer(message)
        ret = neuropil.np_send(
            self._context, _subject._cdata, raw_bytes, len(raw_bytes)
        )
        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        return ret

    def new_identity(
        self, expires_at: float = time.time() + (60 * 60 * 24), secret_key: bytes = None
    ):
        if not isinstance(expires_at, float):
            raise ValueError(f"expires_at needs to be of type `float`")
        if not isinstance(secret_key, bytes) and secret_key != None:
            raise ValueError(f"secret_key needs to be of type `bytes` or `None`")

        if secret_key == None:
            internal_secret_key = ffi.NULL
        else:
            internal_secret_key = ffi.from_buffer(
                "unsigned char(*)[64]", secret_key
            )  # 64 = NP_SECRET_KEY_BYTES
        ffi_token = neuropil.np_new_identity(
            self._context, expires_at, internal_secret_key
        )
        ret = _NeuropilHelper.convert_to_python(self, ffi_token)
        return ret

    def use_identity(self, identity: np_token):
        if not isinstance(identity, np_token):
            raise ValueError(f"identity needs to be of type `np_token`")

        token_dict = _NeuropilHelper.convert_from_python(identity)
        # ffi_token = ffi.new("struct np_token", token_dict)

        ret = neuropil.np_use_identity(self._context, identity._raw)

        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "Could not use identity. Error: {error}".format(
                    error=ffi.string(neuropil.np_error_str(ret))
                ),
                ret,
            )
        return ret

    def get_mx_properties(self, subject: Union[str, bytes, np_subject]):
        subject = _NeuropilHelper.check_subject(subject)

        ret = neuropil.np_get_mx_properties(self._context, subject._cdata)

        if ret == ffi.NULL:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        else:
            ret = _NeuropilHelper.convert_to_python(self, ret)
            ret.subject = subject  # currently no native part of the np_mx_property

        return ret

    def set_mx_properties(
        self, subject: Union[str, bytes, np_subject], mx_property: np_mx_properties
    ):
        subject = _NeuropilHelper.check_subject(subject)
        if not isinstance(mx_property, np_mx_properties):
            raise ValueError(f"mx_property needs to be of type `np_mx_properties`")

        ret = neuropil.np_set_mx_properties(
            self._context,
            subject._cdata,
            _NeuropilHelper.convert_from_python(mx_property),
        )

        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )

        return ret

    def set_userdata(self, userdata):
        self._userdata.data = userdata

    def get_userdata(self):
        return self._userdata.data

    def has_joined(self):
        return neuropil.np_has_joined(self._context)

    def get_route_count(self):
        return neuropil.np_get_route_count(self._context)

    def np_has_receiver_for(self, subject: Union[str, bytes, np_subject]):
        subject = _NeuropilHelper.check_subject(subject)

        return neuropil.np_has_receiver_for(self._context, subject._cdata)

    def get_address(self):
        address = ffi.new("char[500]", b"\0")
        status = neuropil.np_get_address(self._context, address, 255)
        # no optional exception throwing due to the fact that the return is not the fn status
        if status is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(status))),
                status,
            )

        return ffi.string(address).decode("utf-8")

    def get_status(self):
        ret = neuropil.np_get_status(self._context)
        return ret

    def set_attr_bin(
        self, key: bytes, data: bytes, inheritance=neuropil.NP_ATTR_IDENTITY
    ):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(data, str):
            data = data.encode("utf-8")
        data_return = neuropil.np_set_ident_attr_bin(
            self._context, ffi.NULL, inheritance, key, data, len(data)
        )

        if data_return != neuropil.np_data_ok:
            raise NeuropilException(
                f"Could not set attribute. Error code: {data_return}. Please review neuropil_data.h for details",
                data_return,
            )

    def set_authenticate_cb(self, authn_callback):
        self._user_authn_cb = authn_callback
        ret = neuropil.np_set_authenticate_cb(self._context, neuropil._py_authn_cb)
        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        return ret

    def set_authorize_cb(self, authz_callback):
        self._user_authz_cb = authz_callback
        ret = neuropil.np_set_authorize_cb(self._context, neuropil._py_authz_cb)
        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        return ret

    def set_accounting_cb(self, acc_callback):
        self._user_accou_cb = acc_callback
        ret = neuropil.np_set_accounting_cb(self._context, neuropil._py_acc_cb)
        if ret is not neuropil.np_ok:
            raise NeuropilException(
                "{error}".format(error=ffi.string(neuropil.np_error_str(ret))), ret
            )
        return ret


class _NeuropilHelper:
    @staticmethod
    def from_context(context):
        handle = neuropil.np_get_userdata(context)
        if handle == ffi.NULL:
            return None
        return ffi.from_handle(handle)

    @staticmethod
    def convert_struct_field(node: NeuropilNode, s, fields):
        for field, fieldtype in fields:
            if fieldtype.type.kind == "primitive":
                yield (field, getattr(s, field))
            else:
                if field == "data":
                    yield (field, getattr(s, field))
                else:
                    yield (
                        field,
                        _NeuropilHelper.convert_to_python(node, getattr(s, field)),
                    )

    @staticmethod
    def check_subject(subject):
        ret = subject
        if not isinstance(ret, np_subject):
            ret = np_subject.generate(ret)

        if not isinstance(ret, np_subject):
            raise ValueError(
                f"argument `subject` needs to be of type `bytes`, `str` or `np_subject`"
            )
        return ret

    @staticmethod
    def convert_to_python(node: NeuropilNode, s):
        ret = None
        type = None
        try:
            type = ffi.typeof(s)
        except:
            ret = s

        if type == None:
            pass
        elif type.kind == "struct":
            ret = dict(_NeuropilHelper.convert_struct_field(node, s, type.fields))
            if type.cname == "struct np_log_entry":
                ret = np_log_entry(node, s, **ret)
            elif type.cname == "struct np_message":
                ret = np_message(ret, s, **ret)
            elif type.cname == "struct np_token":
                ret = np_token(node, s, **ret)
            elif type.cname == "struct np_id":
                ret = np_id(s)
            elif type.cname == "struct np_subject":
                ret = np_subject(s)
            elif type.cname == "struct np_mx_properties":
                ret = np_mx_properties(node, **ret)
            elif type.cname == "struct np_searchentry":
                ret = np_searchentry(s, **ret)
            elif type.cname == "struct np_searchquery":
                ret = np_searchquery(s, **ret)
            elif type.cname == "struct np_searchresult":
                ret = np_searchresult(s, **ret)
        elif type.kind == "array":
            if type.item.kind == "primitive":
                if type.item.cname == "char":
                    ret = ffi.string(s)
                    try:
                        ret = ret.decode("utf-8")
                    except UnicodeDecodeError:
                        pass
                else:
                    ret = [s[i] for i in range(type.length)]
            else:
                ret = [
                    _NeuropilHelper.convert_to_python(node, s[i])
                    for i in range(type.length)
                ]
        elif type.kind == "primitive":
            if type.item.cname == "char":
                ret = ffi.string(s)
                try:
                    ret = ret.decode("utf-8")
                except UnicodeDecodeError:
                    pass
            else:
                ret = int(s)
        elif type.kind == "pointer":
            if type.item.cname == "char":
                ret = ffi.string(s)
                try:
                    ret = ret.decode("utf-8")
                except UnicodeDecodeError:
                    pass
            else:
                ret = _NeuropilHelper.convert_to_python(node, s[0])
        else:
            print(
                f"NotImplementedError in _NeuropilHelper.convert_to_python: unknown {type.kind}. {type.name} {repr(type)}"
            )
            raise NotImplementedError()
        return ret

    @staticmethod
    def __convert_value_from_python(value):
        ret = value
        if value == None:
            ret = ffi.NULL
        if isinstance(value, str):
            ret = value.encode("utf-8")
        if isinstance(value, np_id):
            ret = value._cdata
        return ret

    @staticmethod
    def __convert_from_python(s: dict, ignore_attr=[]):
        ret = {}
        for key, value in s.items():
            if key not in ignore_attr:
                ret[key] = _NeuropilHelper.__convert_value_from_python(value)
        return ret

    @staticmethod
    def convert_from_python(s):
        ignore_attr = []
        if hasattr(s, "_ignore_at_conversion"):
            ignore_attr = s._ignore_at_conversion + ["_ignore_at_conversion"]

        if isinstance(s, np_id):
            return _NeuropilHelper.__convert_value_from_python(s)
        elif isinstance(s, dict):
            return _NeuropilHelper.__convert_from_python(s, ignore_attr)
        elif hasattr(s, "__dict__"):
            return _NeuropilHelper.__convert_from_python(s.__dict__, ignore_attr)
        else:
            return _NeuropilHelper.__convert_value_from_python(s)


@ffi.def_extern()
def _py_subject_callback(context, message):
    ret = True
    myself = _NeuropilHelper.from_context(context)
    msg = _NeuropilHelper.convert_to_python(myself, message)

    subject_id = str(msg.subject)
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
    return bool(
        myself._user_authn_cb(myself, _NeuropilHelper.convert_to_python(myself, token))
    )


@ffi.def_extern()
def _py_log_write_cb(context, entry):
    myself = _NeuropilHelper.from_context(context)
    if myself:
        myself._user_log_write_cb(
            myself, _NeuropilHelper.convert_to_python(myself, entry)
        )
    return None


@ffi.def_extern()
def _py_authz_cb(context, token):
    myself = _NeuropilHelper.from_context(context)
    return bool(
        myself._user_authz_cb(myself, _NeuropilHelper.convert_to_python(myself, token))
    )


@ffi.def_extern()
def _py_acc_cb(context, token):
    myself = _NeuropilHelper.from_context(context)
    return bool(
        myself._user_accou_cb(myself, _NeuropilHelper.convert_to_python(myself, token))
    )


def np_get_id(to_id: str) -> np_id:
    if isinstance(to_id, str):
        to_id = to_id.encode("utf-8")
    if not isinstance(to_id, bytes):
        raise ValueError(f"to_id needs to be of type `bytes` or `str`")
    npid = ffi.new("np_id")
    neuropil.np_get_id(ffi.addressof(npid), to_id, len(to_id))

    return np_id(npid)
