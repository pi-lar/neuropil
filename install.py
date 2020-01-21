#! /usr/bin/env python3

# Install neuropil library in system

import subprocess
import platform
import glob
import io
import os

from build_info import get_version, get_build_name    
from shutil import copyfile

lib_prefix ="lib"
lib_extension =".so"
install_path = os.path.join("/","usr","local","lib")

build_name = get_build_name()
dir_path = os.path.dirname(os.path.realpath(__file__))

lib_name = f"{lib_prefix}neuropil{lib_extension}"
library_path = os.path.join(dir_path,"build","lib",lib_name)
if not os.path.isfile(library_path):
    print("Please build the neuropil library first")
else:    
    lib_destination_path = os.path.join(install_path,f"{lib_prefix}{build_name}{lib_extension}")
    copyfile(library_path, lib_destination_path)

    symlink_path = os.path.join(install_path,lib_name)
    if os.path.isfile(symlink_path):
        os.remove(symlink_path)
    os.symlink(lib_destination_path, symlink_path)

