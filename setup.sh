#!/bin/bash
set -e

if [ -z "$WOLFSSL_INSTALL" ]; then
    WOLFSSL_INSTALL=/opt/wolfssl
fi
if [ -z "$GNUTLS_INSTALL" ]; then
    GNUTLS_INSTALL=/opt/gnutls
fi
if [ -z "$PROVIDER_PATH" ]; then
    PROVIDER_PATH=/opt/wolfssl-gnutls-wrapper
fi

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

if [ $FIPS_MODE -eq 1 ]; then
    echo "Setting up wolfSSL with FIPS‑ready mode..."

    if [ -n "$WOLFSSL_FIPS_BUNDLE" ]; then
        # User provided a bundle directory – use it verbatim
        if [ ! -d "$WOLFSSL_FIPS_BUNDLE" ]; then
            echo "ERROR: WOLFSSL_FIPS_BUNDLE '$WOLFSSL_FIPS_BUNDLE' is not a directory."
            exit 1
        fi
        echo "Using pre‑downloaded wolfSSL FIPS bundle at '$WOLFSSL_FIPS_BUNDLE'"
        cd "$WOLFSSL_FIPS_BUNDLE"
    else
        # Fresh checkout & FIPS helper
        rm -rf wolfssl/ fips-v5-checkout/

        echo "Cloning wolfSSL repository for FIPS‑ready build..."
        git clone https://github.com/wolfssl/wolfssl.git
        cd wolfssl

        echo "Running FIPS‑ready preparation..."
        ./fips-check.sh linuxv5.2.1 keep

        echo "Moving FIPS directory XXX-fips-test to ../fips-v5-checkout"
        mv XXX-fips-test ../fips-v5-checkout

        cd ..
        rm -rf wolfssl/

        cd fips-v5-checkout
    fi

    ./configure --prefix=$WOLFSSL_INSTALL/ CC=clang --enable-cmac --enable-aesccm --enable-aescfb --enable-keygen 'CFLAGS=-DWOLFSSL_PUBLIC_ASN -DHAVE_PUBLIC_FFDHE -DHAVE_FFDHE_3072 -DHAVE_FFDHE_4096 -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DWOLFSSL_PUBLIC_MP -DWOLFSSL_RSA_KEY_CHECK' --enable-fips=v5 --enable-md5

    make

    echo "Running FIPS hash verification..."
    ./fips-hash.sh

    make

    echo "Running FIPS checks..."
    make check

    sudo make install
    cd ../

else
    if [ ! -d "wolfssl" ]; then
        echo "Cloning wolfSSL repository..."
        git clone --depth=1 https://github.com/wolfssl/wolfssl.git
    fi

    cd ./wolfssl
    ./autogen.sh

    ./configure --prefix=$WOLFSSL_INSTALL/ CC=clang --enable-cmac --with-eccminsz=192 --enable-ed25519 --enable-ed448 --enable-md5 --enable-curve25519 --enable-curve448 --enable-aesccm --enable-aesxts --enable-aescfb --enable-keygen --enable-shake128 --enable-shake256 'CFLAGS=-DWOLFSSL_PUBLIC_ASN -DHAVE_FFDHE_3072 -DHAVE_FFDHE_4096 -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DWOLFSSL_PUBLIC_MP -DWOLFSSL_RSA_KEY_CHECK -DHAVE_FFDHE_Q -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DWOLFSSL_ECDSA_DETERMINISTIC_K -DWOLFSSL_VALIDATE_ECC_IMPORT -DRSA_MIN_SIZE=1024'

    make
    sudo make install
    cd ../
fi

if [ ! -d "gnutls" ]; then
    echo "Cloning GnuTLS repository..."
    git clone https://github.com/wolfssl/gnutls.git
    echo "Checking out to gnutls-wolfssl..."
    cd ./gnutls
    git fetch --all
    git checkout -b gnutls-wolfssl origin/gnutls-wolfssl
else
    cd ./gnutls
    make clean
fi

./bootstrap
autoreconf -fvi

# Base configuration options for GnuTLS
if [ "$OS" = "macos" ]; then
    echo "Configuring GnuTLS for macOS..."

    CONFIG_OPTS="--prefix=$GNUTLS_INSTALL/ --disable-doc --disable-manpages --disable-gtk-doc --disable-full-test-suite --disable-valgrind-tests --disable-dependency-tracking --disable-gost --disable-dsa --enable-srp-authentication"

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

    CONFIG_OPTS="--prefix=$GNUTLS_INSTALL/ --disable-doc --disable-manpages --disable-gtk-doc --disable-gost --disable-dsa --disable-full-test-suite --disable-valgrind-tests --disable-dependency-tracking --enable-srp-authentication"

    if [ $FIPS_MODE -eq 1 ]; then
        CONFIG_OPTS="$CONFIG_OPTS --enable-fips140-mode"
    fi

    ./configure $CONFIG_OPTS 'CFLAGS=-DGNUTLS_WOLFSSL'

    export GNUTLS_FORCE_FIPS_MODE=1

    make -j9
fi

sudo make install
cd ../

cd ./wolfssl-gnutls-wrapper
make
sudo make install PROVIDER_PATH="$PROVIDER_PATH"
cd ../

echo "Build completed successfully"
