#!/usr/bin/env python3
import os, sys, platform
from cffi import FFI

def get_local_target():
    return "linux"


ffibuilder = FFI()
PATH = os.path.dirname(__file__)

np_lib_path = os.path.join(PATH, "..","..","build",'neuropil',"lib")
np_include_path = os.path.join(PATH, "..","..","include")

# This describes the extension module "_neuropil" to produce.
ffibuilder.set_source(
    "_neuropil",
    r"""
        #include "neuropil.h"   // the C header of the library
    """,
    libraries=['neuropil', 'sodium'],   # library name, for the linker
    # extra_objects=[np_lib_path],
    library_dirs=[np_lib_path],
    include_dirs=[np_include_path]
    )

# cdef() expects a string listing the C types, functions and
# globals needed from Python. The string follows the C syntax.
import subprocess

h_files = ['neuropil.h']

for h_file in h_files:
    h_file_path = os.path.join(np_include_path, h_file)
    cc = os.getenv("CC",'clang')

    cmd =[
            cc,"-E",h_file_path,
            "-D__CLANG_MAX_ALIGN_T_DEFINED",
            # "-Ipycparser/utils/fake_libc_include"
            "-DNP_PACKED(x)=","-DNP_API_EXPORT=", "-DNP_ENUM=", "-DNP_CONST_ENUM="
            ]
    if platform.system() == 'Darwin':
        cmd += ["-D__signed=", "-D__builtin_va_list=void*"]
    h_file = subprocess.run(cmd, stdout=subprocess.PIPE).stdout.decode('utf-8')
    ffibuilder.cdef(h_file, packed=True)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
