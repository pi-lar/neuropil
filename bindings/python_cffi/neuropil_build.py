#!/usr/bin/env python3
import os, sys
from cffi import FFI

def get_local_target():
	return "linux"


ffibuilder = FFI()
PATH = os.path.dirname(__file__)

np_lib_path = os.path.join(PATH, f"../../build/{get_local_target()}/lib")
np_include_path = os.path.join(PATH, "../../include")

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

h_file_path = os.path.join(np_include_path, 'neuropil.h')

cc = "clang"
if os.getenv("CC"):
    cc = os.getenv("CC")
h_file = subprocess.run([
	cc,"-E",h_file_path,#"-Ipycparser/utils/fake_libc_include",
	"-D__CLANG_MAX_ALIGN_T_DEFINED",
	"-DNP_PACKED(x)=","-DNP_API_EXPORT=", "-DNP_ENUM="
	], stdout=subprocess.PIPE).stdout.decode('utf-8')

#print("START Neuropil.h")
#print(h_file)
#print("END   Neuropil.h")

ffibuilder.cdef(h_file, packed=True)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
