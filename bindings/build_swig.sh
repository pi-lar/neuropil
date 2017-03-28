
rm python/*

swig -python -outdir python -o python/neuropil_wrap.c neuropil.i

cp setup.py python/setup.py
cd python

python setup.py build




