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

if [ "$OS" = "macos" ]; then
    echo "Installing macOS dependencies..."
    brew update
    for pkg in openssl autoconf automake coreutils libtool gmp nettle p11-kit libtasn1 libunistring gettext bison gtk-doc libev; do
        brew install $pkg || true
    done
    for pkg in nettle wget p11-kit libtasn1 libunistring; do
        brew upgrade $pkg || true
    done

    export PATH="/usr/local/opt/gettext/bin:/opt/homebrew/opt/gettext/bin:$PATH"
    export PATH="/usr/local/opt/bison/bin:/opt/homebrew/opt/bison/bin:$PATH"
fi

if [ ! -d "wolfssl" ]; then
    echo "Cloning wolfSSL repository..."
    git clone --depth=1 https://github.com/wolfssl/wolfssl.git
fi

cd ./wolfssl
./autogen.sh

if [ "$OS" = "macos" ]; then
    echo "Configuring wolfSSL for macOS..."
    ./configure --prefix=/opt/wolfssl/ CC=clang --enable-cmac --enable-ed25519 --enable-ed448 --enable-curve25519 --enable-curve448 --enable-aesccm --enable-aesxts
else
    echo "Configuring wolfSSL for Linux..."
    ./configure --prefix=/opt/wolfssl/ --enable-cmac --enable-ed25519 --enable-ed448 --enable-curve25519 --enable-curve448 --enable-aesccm --enable-aesxts
fi

make
sudo make install
cd ../

if [ ! -d "gnutls" ]; then
    echo "Cloning GnuTLS repository..."
    git clone https://github.com/gasbytes/gnutls.git

    echo "Checking out to gnutls-wolfssl..."
    cd ./gnutls
    git fetch --all
    git checkout -b gnutls-wolfssl origin/gnutls-wolfssl
else
    cd ./gnutls
fi

./bootstrap

autoreconf -fvi

if [ "$OS" = "macos" ]; then
    echo "Configuring GnuTLS for macOS..."
    CFLAGS="-I$(brew --prefix libunistring)/include -I$(brew --prefix gmp)/include -I$(brew --prefix libev)/include -DGNUTLS_WOLFSSL" \
    LDFLAGS="-L$(brew --prefix libunistring)/lib -L$(brew --prefix gmp)/lib -L$(brew --prefix libev)/lib -L$(brew --prefix bison)/lib" \
    GMP_CFLAGS="-I$(brew --prefix gmp)/include" \
    GMP_LIBS="-L$(brew --prefix gmp)/lib -lgmp" \
    PKG_CONFIG_PATH="$(brew --prefix libev)/lib/pkgconfig:$(brew --prefix gmp)/lib/pkgconfig:$PKG_CONFIG_PATH" \
    CC=clang \
    ./configure --prefix=/opt/gnutls/ --disable-doc --disable-manpages --disable-gtk-doc --disable-full-test-suite --disable-valgrind-tests --disable-dependency-tracking --disable-gost
    make -j$(sysctl -n hw.ncpu)
else
    echo "Configuring GnuTLS for Linux..."
    ./configure --prefix=/opt/gnutls/ --disable-doc --disable-manpages --disable-gtk-doc --disable-gost CFLAGS=-DGNUTLS_WOLFSSL
    make -j9
fi

sudo make install
cd ../

cd ./wolfssl-gnutls-wrapper
make
sudo make install
cd ../

echo "Build completed successfully"
