#
# neuropil is copyright 2016-2017 by pi-lar GmbH
# Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
#

work_dir=${PWD}

echo "building in: $work_dir"

rm -r build

ARCHFLAGS='-arch x86_64' python setup.py build

sudo install_name_tool -change build/lib/libneuropil.dylib $work_dir/../build/lib/libneuropil.dylib $work_dir/build/lib.macosx-10.11-intel-2.7/_neuropil.so

python test_neuropil.py
