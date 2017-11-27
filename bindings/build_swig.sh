
work_dir=${PWD}

echo "building in: $work_dir"

rm -r python
mkdir python

swig -python -outdir python -o neuropil_python.c neuropil.i

cp setup.py python/setup.py

# python setup.py build
# -stdlib=libc++ ??

clang -Wall -c -I/usr/include/python2.7 -I$work_dir/../include neuropil_python.c -o python/neuropil_python.o

cd python
clang -dynamiclib -L/usr/lib -lpython2.7 -L$work_dir/../build/lib -lneuropil neuropil_python.o -o _neuropil.dylib
clang -dynamiclib -L/usr/lib -lpython2.7 -L$work_dir/../build/lib -lneuropil neuropil_python.o -o _neuropil.so

otool -L _neuropil.so
otool -L _neuropil.dylib

# osx security settings require the folloiwing steps if testing locally
sudo install_name_tool -change build/lib/libneuropil.dylib $work_dir/../build/lib/libneuropil.dylib $work_dir/python/_neuropil.so
sudo install_name_tool -change build/lib/libneuropil.dylib $work_dir/../build/lib/libneuropil.dylib $work_dir/python/_neuropil.dylib

cp ../test_neuropil.py test_neuropil.py
python test_neuropil.py
