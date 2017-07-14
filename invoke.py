#!/usr/bin/env bash

killall neuropil_raspberry
rm *.log core
export DYLD_LIBRARY_PATH=build/lib
export LD_LIBRARY_PATH=build/lib
./bin/neuropil_raspberry -g 1 -b 3334 1&2> neuropil_raspberry.log < /dev/null &
sleep 5s
head -20 neuropil_raspberry.log
