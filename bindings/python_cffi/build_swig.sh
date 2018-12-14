#!/bin/bash
#
# neuropil is copyright 2016-2017 by pi-lar GmbH
# Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
#
work_dir=$(dirname "$0")
cd $work_dir;
echo "building in: $work_dir"

rm -r $work_dir/build

unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     machine=Linux;;
    Darwin*)    machine=Mac;;
    CYGWIN*)    machine=Cygwin;;
    MINGW*)     machine=MinGw;;
    *)          machine="UNKNOWN:${unameOut}"
esac


ARCHFLAGS='-arch x86_64' python3 setup.py build


if [ $? == 0 ] && [ ${machine} == Mac ]
then
    echo "Trying to use name tool to link into build library"
    sudo install_name_tool -change build/lib/libneuropil.dylib $work_dir/../../build/lib/libneuropil.dylib $work_dir/build/lib.macosx-10.11-x86_64-3.6/_neuropil.abi3.so
fi

exit $?