#!/usr/bin/env bash

echo "removing old instances"
killall neuropil_raspberry
rm *.log core
export DYLD_LIBRARY_PATH=build/lib
export LD_LIBRARY_PATH=build/lib
echo "start program"
./bin/neuropil_raspberry -d -3 -g 1 -b 3334 >  neuropil_raspberry.log 2>&1 &
echo "wait program"
sleep 3s
head -50 neuropil_raspberry.log
echo "done"
