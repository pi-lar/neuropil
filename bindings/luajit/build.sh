#!/bin/bash
#
# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0
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
