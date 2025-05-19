#!/bin/bash

set -e

# Check if FIPS mode is enabled via command line argument
FIPS_MODE=0
if [ "$1" = "fips" ]; then
    FIPS_MODE=1
    echo "Building GnuTLS with FIPS 140 mode enabled"
else
    echo "Building GnuTLS without FIPS 140 mode"
fi

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

    CONFIG_OPTS="--prefix=/opt/gnutls/ --disable-doc --disable-manpages --disable-gtk-doc --disable-full-test-suite --disable-valgrind-tests --disable-dependency-tracking --disable-gost --disable-dsa --enable-srp-authentication"

    if [ $FIPS_MODE -eq 1 ]; then
        CONFIG_OPTS="$CONFIG_OPTS --enable-fips140-mode"
    fi

    CFLAGS="-I$(brew --prefix libunistring)/include -I$(brew --prefix gmp)/include -I$(brew --prefix libev)/include -DGNUTLS_WOLFSSL" \
    LDFLAGS="-L$(brew --prefix libunistring)/lib -L$(brew --prefix gmp)/lib -L$(brew --prefix libev)/lib -L$(brew --prefix bison)/lib" \
    GMP_CFLAGS="-I$(brew --prefix gmp)/include" \
    GMP_LIBS="-L$(brew --prefix gmp)/lib -lgmp" \
    PKG_CONFIG_PATH="$(brew --prefix libev)/lib/pkgconfig:$(brew --prefix gmp)/lib/pkgconfig:$PKG_CONFIG_PATH" \
    CC=clang \
    ./configure $CONFIG_OPTS

    make -j$(sysctl -n hw.ncpu)

else
    echo "Configuring GnuTLS for Linux..."
    autoreconf -fvi

    CONFIG_OPTS="--prefix=/opt/gnutls/ --disable-doc --disable-manpages --disable-gtk-doc --disable-gost --disable-dsa --enable-srp-authentication"

    if [ $FIPS_MODE -eq 1 ]; then
        CONFIG_OPTS="$CONFIG_OPTS --enable-fips140-mode"
    fi

    ./configure $CONFIG_OPTS CFLAGS=-DGNUTLS_WOLFSSL

    make -j9
fi

sudo make install
cd ../
