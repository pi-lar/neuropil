#!/usr/bin/env python3
import os, sys, platform
from sysconfig import get_paths
from cffi import FFI

ffibuilder = FFI()
PATH = os.path.dirname(os.path.abspath(__file__))

library_dirs = [
    os.path.join(PATH, "..","..","build",'neuropil',"lib"), #dev build
    os.getenv("LD_LIBRARY_PATH",""),
    os.getenv("DYLD_LIBRARY_PATH",""),
    os.path.join("/usr", "lib"),
    os.path.join("/usr", "lib", "neuropil"),
]

include_dirs = [
    os.path.join(PATH, "..", "..", "include"), # dev build
    os.path.join("/usr","include", "neuropil"),
    os.path.join("/usr","local","include", "neuropil"),
]



with open(os.path.join(PATH,"include", "neuropil_comb.h"),"r") as f:
    ffibuilder.cdef(f.read(), packed=True, override=True)

ffibuilder.cdef('''
    extern "Python" bool _py_subject_callback(np_context* context, struct np_message*);
    extern "Python" bool _py_authn_cb(np_context* context, struct np_token*);
    extern "Python" bool _py_authz_cb(np_context* context, struct np_token*);
    extern "Python" bool _py_acc_cb(np_context* context, struct np_token*);
''', packed=True, override=True)

ffibuilder.set_source(
    "_neuropil",
    """
        #include "neuropil.h"
        #include "neuropil_data.h"
        #include "neuropil_attributes.h"
        #include "neuropil_log.h"
    """,
    libraries=['neuropil'],   # library name, for the linker
    library_dirs=library_dirs,
    include_dirs=include_dirs

)


#if __name__ == "__main__":
ffibuilder.compile(verbose=True)
