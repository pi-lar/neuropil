#!/bin/bash
(
    cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
    mkdir -p /usr/local/include/neuropil
    cp ../../include/neuropil* /usr/local/include/neuropil
    install ../../build/neuropil/lib/libneuropil.so /usr/local/lib
    ldconfig
)