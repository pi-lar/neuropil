#!/usr/bin/env bash

export DYLD_LIBRARY_PATH=build/lib 
export LD_LIBRARY_PATH=build/lib 
./bin/neuropil_raspberry -g 1
