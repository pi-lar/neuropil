#!/bin/bash
cd ~
wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz -O LATEST.tar.gz
mkdir -p ./libsodium
tar -xzf LATEST.tar.gz -C ./libsodium
rm LATEST.tar.gz
cd libsodium/libsodium-stable
./configure
make
make check
sudo make install
