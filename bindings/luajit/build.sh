#!/bin/bash
#
# neuropil is copyright 2016-2020 by pi-lar GmbH
# Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
#
work_dir=$(dirname "$0")
cd $work_dir;

mkdir -p build

CC=${CC:-clang} 

echo "Precompiling neuropil.h"
CDEF=$(${CC} -E ../../include/neuropil.h | egrep -v "^#")

if [ $? == 0 ]
then
  echo "Genereating LUA binding"
  echo -n "local ffi=require('ffi'); ffi.cdef[=============[${CDEF}]=============]; return ffi.load('neuropil')" > build/neuropil_ffi.lua
  if [ $? == 0 ]
  then
    echo "Genereated LUA binding in $work_dir/build/neuropil_ffi.lua"
  fi
fi

exit $?