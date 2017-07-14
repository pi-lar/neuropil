#!/usr/bin/env bash

rm *.log core
export DYLD_LIBRARY_PATH=build/lib
export LD_LIBRARY_PATH=build/lib
./bin/neuropil_raspberry -g 1 -b 3334
