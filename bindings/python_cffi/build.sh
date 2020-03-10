#!/bin/bash
#
# neuropil is copyright 2016-2020 by pi-lar GmbH
# Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
#
base_dir=$PWD
work_dir=$(dirname "$0")
VERSION="$1"

(
    cd $work_dir;
    echo "working in \"$work_dir\""

    unameOut="$(uname -s)"
    case "${unameOut}" in
        NetBSD*)    machine=BSD;;
        OpenBSD*)   machine=BSD;;
        FreeBSD*)   machine=BSD;;
        Linux*)     
            machine=Linux;
            echo "Updating version in setup.py"
            sed -i "s|version = '.*',|version = '$VERSION',|g" setup.py;;
        Darwin*)    
            machine=Mac;
            echo "Updating version in setup.py"
            sed -i "" "s|version = '.*',|version = '$VERSION',|g" setup.py;;
        CYGWIN*)    machine=Cygwin;;
        MINGW*)     machine=MinGw;;
        *)          machine="UNKNOWN:${unameOut}"
    esac


    ARCHFLAGS='-arch x86_64' python3 setup.py build

    last=$?
    if [ $last == 0 ]
    then
        echo "Generated PYTHON binding in ${work_dir}"

        if [ $last == 0 ]
        then
            echo "Generated PYTHON binding in ${work_dir}"
            pip3 install -e .  
        fi

        if [ $last == 0 ] && [ ${machine} == Mac ]
        then
            echo "Trying to use name tool to link into build library in ${work_dir}/_neuropil.abi3.so"
            sudo install_name_tool -change build/linux/lib/libneuropil.dylib ${base_dir}/build/linux/lib/libneuropil.dylib ./_neuropil.abi3.so
            last=$?
        fi
    fi

exit $last
)

