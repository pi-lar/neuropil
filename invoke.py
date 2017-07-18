#!/usr/bin/env bash

killall neuropil_raspberry
rm *.log core
export DYLD_LIBRARY_PATH=build/lib
export LD_LIBRARY_PATH=build/lib
./bin/neuropil_raspberry -d -3 -g 1 -b 3334 >  neuropil_raspberry.log 2> neuropil_raspberry.log < neuropil_raspberry.log &
sleep 3s
head -20 neuropil_raspberry.log
