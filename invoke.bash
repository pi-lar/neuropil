#!/usr/bin/env bash

PROG="neuropil_raspberry"
ARGS="-d -1"

while [[ $# -gt 0 ]]
do
key="$1"
case $key in
    -p|--program)
    PROG="$2"
    shift # past argument
    ;;
    -a|--args)
    ARGS="$2"
    shift # past argument
    ;;
    *)
            # unknown option
    ;;
esac
shift # past argument or value
done

echo "removing old instances"
killall ${PROG}
rm *.log *core*
export DYLD_LIBRARY_PATH=build/lib
export LD_LIBRARY_PATH=build/lib
echo "start program"
./bin/${PROG} ${ARGS} > ${PROG}.log 2>&1 &
echo "wait program"
sleep 3s
chmod 775 ${PROG}.log
head -50 ${PROG}.log
echo "background startup of ${PROG} ${ARGS} is done"
