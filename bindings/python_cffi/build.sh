#!/bin/bash
#
# neuropil is copyright 2016-2019 by pi-lar GmbH
# Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
#
work_dir=$(dirname "$0")
VERSION="$1"

cd $work_dir;

unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     machine=Linux;;
    Darwin*)    machine=Mac;;
    CYGWIN*)    machine=Cygwin;;
    MINGW*)     machine=MinGw;;
    *)          machine="UNKNOWN:${unameOut}"
esac


ARCHFLAGS='-arch x86_64' python3 setup.py build

echo "Updating version in setup.py"
sed -i "s/version = '.*',/version = '$VERSION',/g"  setup.py
last=$?
if [ $last == 0 ]
then
    echo "Generated PYTHON binding in $work_dir"

    if [ $last == 0 ] && [ ${machine} == Mac ]
    then
        echo "Trying to use name tool to link into build library"
        sudo install_name_tool -change build/darwin/lib/libneuropil.dylib $work_dir/../../build/darwin/lib/libneuropil.dylib $work_dir/build/darwin/lib.macosx-10.11-x86_64-3.6/_neuropil.abi3.so
        last=$?
    fi

    if [ $last == 0 ]
    then
        echo "Generated PYTHON binding in $work_dir"
        pip3 install -e .  
    fi
fi


exit $last