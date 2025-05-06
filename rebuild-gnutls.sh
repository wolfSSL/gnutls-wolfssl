#!/bin/bash

set -e

get_os() {
    case "$(uname -s)" in
        Darwin*)    echo "macos";;
        Linux*)     echo "linux";;
        *)          echo "unknown";;
    esac
}

OS=$(get_os)
echo "Detected OS: $OS"

cd ./gnutls

if [ "$OS" = "macos" ]; then
    echo "Configuring GnuTLS for macOS..."
    autoreconf -fvi
    CFLAGS="-I$(brew --prefix libunistring)/include -I$(brew --prefix gmp)/include -I$(brew --prefix libev)/include -DGNUTLS_WOLFSSL" \
    LDFLAGS="-L$(brew --prefix libunistring)/lib -L$(brew --prefix gmp)/lib -L$(brew --prefix libev)/lib -L$(brew --prefix bison)/lib" \
    GMP_CFLAGS="-I$(brew --prefix gmp)/include" \
    GMP_LIBS="-L$(brew --prefix gmp)/lib -lgmp" \
    PKG_CONFIG_PATH="$(brew --prefix libev)/lib/pkgconfig:$(brew --prefix gmp)/lib/pkgconfig:$PKG_CONFIG_PATH" \
    CC=clang \
    ./configure --prefix=/opt/gnutls/ --disable-doc --disable-manpages --disable-gtk-doc --disable-full-test-suite --disable-valgrind-tests --disable-dependency-tracking --disable-gost --enable-srp-authentication
    make -j$(sysctl -n hw.ncpu)
else
    echo "Configuring GnuTLS for Linux..."
    autoreconf -fvi
    ./configure --prefix=/opt/gnutls/ --disable-doc --disable-manpages --disable-gtk-doc --disable-gost --enable-srp-authentication CFLAGS=-DGNUTLS_WOLFSSL
    make -j9
fi

sudo make install
cd ../
