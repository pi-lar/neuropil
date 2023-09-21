# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0
from _neuropil import lib as neuropil, ffi

from neuropil import NeuropilCluster, NeuropilException, NeuropilNode, _NeuropilHelper
from neuropil import np_searchentry, np_searchquery, np_searchresult

from typing import List, Union
import time, copy, inspect


class NeuropilSearchCluster(NeuropilCluster):
    def __init__(
        self,
        count,
        port_range=3000,
        host=b"localhost",
        proto=b"udp4",
        auto_run=True,
        log_file_prefix="",
        **settings,
    ):
        self.index_nodes = []

        if count <= 0:
            raise ValueError("The `count` of a cluster needs to be greater than 0")

        if not isinstance(port_range, list):
            port_range = range(port_range, port_range + count)
        if not isinstance(proto, list):
            proto = [proto] * count

        for c in range(0, count):
            port = port_range[c]
            log_file = f"{log_file_prefix}{host}_{port}.log"
            node = NeuropilSearchNode(
                port=port,
                host=host,
                proto=proto[c],
                auto_run=auto_run,
                log_file=log_file,
                **settings,
            )
            self.index_nodes.append(node)

    def __getattr__(self, name):
        if self.index_nodes:
            first_attr = object.__getattribute__(self.index_nodes[0], name)
            if hasattr(first_attr, "__call__"):

                def wrapper_fn(*args, **kwargs):
                    ret = []
                    for node in self.index_nodes:
                        attr = object.__getattribute__(node, name)
                        ret.append((node, attr(*args, **kwargs)))
                    return ret

                return wrapper_fn
            else:
                return first_attr
        raise AttributeError(f"{self.__class__.__name__}.{name} is invalid.")


class NeuropilSearchNode(NeuropilNode):
    def __init__(self, port: int, host: str, proto: str, auto_run: bool, **settings):
        super().__init__(
            port=port, host=host, proto=proto, auto_run=auto_run, **settings
        )

        self._search_settings = neuropil.np_default_searchsettings()
        setting_type = ffi.typeof(self._search_settings[0])

        for key, cdata in setting_type.fields:
            if key in settings:
                setattr(
                    self._search_settings,
                    key,
                    _NeuropilHelper.convert_from_python(settings[key]),
                )

        self.search = neuropil.np_searchnode_init(self._context, self._search_settings)

        self.queries = {}
        self.entries = {}
        self.results = {}

    def add_searchentry(self, key, search_text: str, **attributes):
        self.entries[key] = ffi.new("struct np_searchentry*")

        attr = ffi.new("np_datablock_t[]", 10240)
        if neuropil.np_init_datablock(attr, 10240) == neuropil.np_data_ok:
            for attribute_key, attribute_value in attributes.items():
                data_conf = {
                    "key": _NeuropilHelper.convert_from_python(attribute_key),
                    "type": neuropil.NP_DATA_TYPE_STR,
                    "data_size": len(attribute_value),
                }
                r = neuropil.np_set_data(
                    attr,
                    data_conf,
                    {
                        "str": ffi.from_buffer(
                            "char*",
                            _NeuropilHelper.convert_from_python(attribute_value),
                        )
                    },
                )
                # print ("add attribute data", attribute_key, attribute_value, r==neuropil.np_data_ok, len(attribute_value),  _NeuropilHelper.convert_from_python(attribute_value))

            # add the search entry to our selected
            if neuropil.pysearch_entry(
                self._context,
                self.entries[key],
                _NeuropilHelper.convert_from_python(search_text),
                attr,
            ):
                return True
            else:
                return False

    def query(self, key, search_text: str, search_probability=0.75, **attributes):
        self.queries[key] = ffi.new("struct np_searchquery*")

        attr = ffi.new("np_datablock_t[]", 10240)
        if neuropil.np_init_datablock(attr, 10240) == neuropil.np_data_ok:
            for attribute_key, attribute_value in attributes.items():
                data_conf = {
                    "key": _NeuropilHelper.convert_from_python(attribute_key),
                    "type": neuropil.NP_DATA_TYPE_STR,
                    "data_size": len(attribute_value),
                }
                r = neuropil.np_set_data(
                    attr,
                    data_conf,
                    {
                        "str": ffi.from_buffer(
                            "char*",
                            _NeuropilHelper.convert_from_python(attribute_value),
                        )
                    },
                )
                # print ("add attribute data", attribute_key, attribute_value, r==neuropil.np_data_ok, len(attribute_value),  _NeuropilHelper.convert_from_python(attribute_value))

            if neuropil.pysearch_query(
                self._context,
                search_probability,
                self.queries[key],
                _NeuropilHelper.convert_from_python(search_text),
                attr,
            ):
                return True
            else:
                return False

    def get_queryresult(self, key) -> List[np_searchresult]:
        size = neuropil.pysearch_pullresult_size(self._context, self.queries[key])
        self.results[key] = ffi.new("struct np_searchresult[]", size)
        neuropil.pysearch_pullresult(
            self._context, self.queries[key], self.results[key], size
        )
        search_results = []
        for result in self.results[key]:
            search_results.append(_NeuropilHelper.convert_to_python(self, result))
        return search_results
