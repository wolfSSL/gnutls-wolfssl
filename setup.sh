#!/bin/bash

set -e

if [ ! -d "wolfssl" ]; then
    git clone --depth=1 https://github.com/wolfssl/wolfssl.git
fi

cd ./wolfssl
./autogen.sh
./configure --prefix=/opt/wolfssl/
make
sudo make install
cd ../

if [ ! -d "gnutls" ]; then
    git clone --depth=1 https://github.com/gnutls/gnutls.git
fi

cd ./gnutls
./bootstrap
git apply ../patch.diff
autoreconf -fvi
./configure --prefix=/opt/gnutls/ --disable-doc --disable-manpages --disable-gtk-doc
make -j9
sudo make install
cd ../

cd ./wolfssl-gnutls-wrapper
make
sudo make install
cd ../
