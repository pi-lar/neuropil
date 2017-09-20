
rm -r python/*

swig -python -outdir python -o python/neuropil_wrap.c neuropil.i

cp setup.py python/setup.py

cd python

# python setup.py build
# -stdlib=libc++ ??

clang -Wall -c -I/usr/include/python2.7 -I/Volumes/SAFE/net.pi-lar/repositories/neuropil/include neuropil_wrap.c -o neuropil_wrap.o
clang -dynamiclib -L/usr/lib -lpython2.7 -L/Volumes/SAFE/net.pi-lar/repositories/neuropil/build/lib -lneuropil neuropil_wrap.o -o _neuropil.dylib
clang -dynamiclib -L/usr/lib -lpython2.7 -L/Volumes/SAFE/net.pi-lar/repositories/neuropil/build/lib -lneuropil neuropil_wrap.o -o _neuropil.so

otool -L _neuropil.so
otool -L _neuropil.dylib

# osx security settings require the folloiwing steps if testing locally
sudo install_name_tool -change build/lib/libneuropil.dylib /Volumes/SAFE/net.pi-lar/repositories/neuropil/build/lib/libneuropil.dylib /Volumes/SAFE/net.pi-lar/repositories/neuropil/bindings/python/_neuropil.so
sudo install_name_tool -change build/lib/libneuropil.dylib /Volumes/SAFE/net.pi-lar/repositories/neuropil/build/lib/libneuropil.dylib /Volumes/SAFE/net.pi-lar/repositories/neuropil/bindings/python/_neuropil.dylib

cp ../test_neuropil.py test_neuropil.py
python test_neuropil.py
