#!/bin/bash
set -e

# Default values
DEFAULT_GNUTLS_VERSION="3.8.9"
FIPS_MODE=0
GNUTLS_VERSION=""

# ============================================================================
# Help function
# ============================================================================
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [fips] [VERSION]

Build script for wolfSSL and GnuTLS with optional FIPS 140 mode support.

ARGUMENTS:
    fips            Enable FIPS 140 mode for the build
    VERSION         GnuTLS branch version (e.g., 3.8.9, 3.8.11)
                    The script will checkout branch: gnutls-wolfssl-VERSION
                    Default version: $DEFAULT_GNUTLS_VERSION

OPTIONS:
    -h, --help      Show this help message and exit

EXAMPLES:
    $(basename "$0")
        Build without FIPS mode, using default GnuTLS branch (gnutls-wolfssl-$DEFAULT_GNUTLS_VERSION)

    $(basename "$0") 3.8.11
        Build without FIPS mode, using GnuTLS branch gnutls-wolfssl-3.8.11

    $(basename "$0") fips
        Build with FIPS 140 mode enabled, using default GnuTLS branch (gnutls-wolfssl-$DEFAULT_GNUTLS_VERSION)

    $(basename "$0") fips 3.8.11
        Build with FIPS 140 mode enabled, using GnuTLS branch gnutls-wolfssl-3.8.11

ENVIRONMENT VARIABLES:
    WOLFSSL_INSTALL     Installation path for wolfSSL (default: /opt/wolfssl)
    GNUTLS_INSTALL      Installation path for GnuTLS (default: /opt/gnutls)
    PROVIDER_PATH       Path for wolfssl-gnutls-wrapper (default: /opt/wolfssl-gnutls-wrapper)
    NETTLE_INSTALL      Installation path for nettle 3.10 (default: /opt/nettle, only used for GnuTLS 3.8.11+)
    WOLFSSL_FIPS_BUNDLE Path to pre-downloaded wolfSSL FIPS bundle (optional, FIPS mode only)

NOTES:
    - The script automatically detects macOS or Linux and installs appropriate dependencies
    - On macOS, Homebrew is required for dependency installation
    - If wolfSSL is already installed system-wide (detectable via pkg-config),
      the script will use it instead of building from source
    - FIPS mode requires access to the wolfSSL FIPS source repository

EOF
    exit 0
}

# ============================================================================
# Parse arguments
# ============================================================================
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                ;;
            fips)
                FIPS_MODE=1
                shift
                ;;
            *)
                # Assume it's a version number
                if [[ "$1" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
                    GNUTLS_VERSION="$1"
                else
                    echo "ERROR: Unknown argument '$1'"
                    echo "Use --help for usage information"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Set default version if not specified
    if [ -z "$GNUTLS_VERSION" ]; then
        GNUTLS_VERSION="$DEFAULT_GNUTLS_VERSION"
        GNUTLS_BRANCH="gnutls-wolfssl"
    else
        GNUTLS_BRANCH="gnutls-wolfssl-$GNUTLS_VERSION"
    fi
}

# ============================================================================
# Main script starts here
# ============================================================================

# Parse command line arguments
parse_arguments "$@"

# Set installation paths with defaults
if [ -z "$WOLFSSL_INSTALL" ]; then
    WOLFSSL_INSTALL=/opt/wolfssl
fi
if [ -z "$GNUTLS_INSTALL" ]; then
    GNUTLS_INSTALL=/opt/gnutls
fi
if [ -z "$PROVIDER_PATH" ]; then
    PROVIDER_PATH=/opt/wolfssl-gnutls-wrapper
fi
if [ -z "$NETTLE_INSTALL" ]; then
    NETTLE_INSTALL=/opt/nettle
fi

# Print configuration
echo "=============================================="
echo "Build Configuration:"
echo "=============================================="
if [ $FIPS_MODE -eq 1 ]; then
    echo "  FIPS 140 Mode:    ENABLED"
else
    echo "  FIPS 140 Mode:    DISABLED"
fi
echo "  GnuTLS Version:   $GNUTLS_VERSION"
echo "  GnuTLS Branch:    $GNUTLS_BRANCH"
echo "  wolfSSL Install:  $WOLFSSL_INSTALL"
echo "  GnuTLS Install:   $GNUTLS_INSTALL"
echo "  Provider Path:    $PROVIDER_PATH"
echo "  Nettle Install:   $NETTLE_INSTALL"
echo "=============================================="
echo ""

get_os() {
    case "$(uname -s)" in
        Darwin*)    echo "macos";;
        Linux*)     echo "linux";;
        *)          echo "unknown";;
    esac
}
OS=$(get_os)
echo "Detected OS: $OS"

detect_system_wolfssl() {
    command -v pkg-config >/dev/null 2>&1 || return 1
    pkg-config --exists wolfssl || return 1
}

USE_SYSTEM_WOLFSSL=0
if detect_system_wolfssl; then
    USE_SYSTEM_WOLFSSL=1
    echo "Found system wolfSSL via pkg-config: $(pkg-config --modversion wolfssl 2>/dev/null || echo unknown)"
    # If we end up using system wolfSSL, make WOLFSSL_INSTALL point to its prefix
    if command -v pkg-config >/dev/null 2>&1; then
        # e.g. /usr/lib/x86_64-linux-gnu -> /usr
        WOLFSSL_INSTALL="${WOLFSSL_INSTALL:-$(pkg-config --variable=libdir wolfssl 2>/dev/null | sed 's#/lib.*##')}"
    fi
    : "${WOLFSSL_INSTALL:=/usr}"
fi

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
    if [ "$USE_SYSTEM_WOLFSSL" -eq 1 ]; then
        echo "Using system wolfSSL. Skipping wolfSSL build."
    else
        echo "Setting up wolfSSL with FIPS-ready mode..."

        if [ -n "$WOLFSSL_FIPS_BUNDLE" ]; then
            # User provided a bundle directory – use it verbatim
            if [ ! -d "$WOLFSSL_FIPS_BUNDLE" ]; then
                echo "ERROR: WOLFSSL_FIPS_BUNDLE '$WOLFSSL_FIPS_BUNDLE' is not a directory."
                exit 1
            fi
            echo "Using pre-downloaded wolfSSL FIPS bundle at '$WOLFSSL_FIPS_BUNDLE'"
            cd "$WOLFSSL_FIPS_BUNDLE"
        else
            # Fresh checkout & FIPS helper
            rm -rf wolfssl/ fips-v5-checkout/

            echo "Cloning fips-src"
            git clone git@github.com:wolfSSL/fips-src.git

            echo "Cloning wolfSSL repository for FIPS-ready build..."
            git clone https://github.com/wolfssl/wolfssl.git
            cd wolfssl

            echo "Running FIPS-v5.2.4 preparation..."
            cp ../fips-src/fips-check-PILOT.sh .
            chmod +x fips-check-PILOT.sh
            ./fips-check-PILOT.sh v5.2.4 keep

            echo "Moving FIPS directory XXX-fips-test to ../fips-v5-checkout"
            mv XXX-fips-test ../fips-v5-checkout

            cd ..
            rm -rf wolfssl/

            cd fips-v5-checkout
        fi

        ./configure --prefix=$WOLFSSL_INSTALL/ CC=clang --enable-cmac --enable-aesccm --enable-keygen 'CFLAGS=-DWOLFSSL_PUBLIC_ASN -DHAVE_PUBLIC_FFDHE -DHAVE_FFDHE_3072 -DHAVE_FFDHE_4096 -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DWOLFSSL_PUBLIC_MP -DWOLFSSL_RSA_KEY_CHECK -DNO_MD5' --enable-fips=v5

        make

        echo "Running FIPS hash verification..."
        ./fips-hash.sh

        make

        echo "Running FIPS checks..."
        make check

        sudo make install
        cd ../
    fi
else
    if [ "$USE_SYSTEM_WOLFSSL" -eq 1 ]; then
        echo "Using system wolfSSL. Skipping wolfSSL build."
    else
        if [ ! -d "wolfssl" ]; then
            echo "Cloning wolfSSL repository..."
            git clone --depth=1 https://github.com/wolfssl/wolfssl.git
        fi

        cd ./wolfssl
        ./autogen.sh

        ./configure --prefix=$WOLFSSL_INSTALL/ CC=clang --enable-cmac --with-eccminsz=192 --enable-ed25519 --enable-ed448 --enable-md5 --enable-curve25519 --enable-curve448 --enable-aesccm --enable-aesxts --enable-aescfb --enable-keygen --enable-shake128 --enable-shake256 'CFLAGS=-DWOLFSSL_PUBLIC_ASN -DHAVE_FFDHE_3072 -DHAVE_FFDHE_4096 -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DWOLFSSL_PUBLIC_MP -DWOLFSSL_RSA_KEY_CHECK -DHAVE_FFDHE_Q -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DWOLFSSL_ECDSA_DETERMINISTIC_K -DWOLFSSL_VALIDATE_ECC_IMPORT -DRSA_MIN_SIZE=1024 -DWOLFSSL_AES_COUNTER'

        make
        sudo make install
        cd ../
    fi
fi

if [ ! -d "gnutls" ]; then
    echo "Cloning GnuTLS repository..."
    git clone https://github.com/wolfssl/gnutls.git
    echo "Checking out to $GNUTLS_BRANCH..."
    cd ./gnutls
    git fetch --all
    git checkout -b "$GNUTLS_BRANCH" "origin/$GNUTLS_BRANCH"
else
    cd ./gnutls
    echo "GnuTLS directory exists. Cleaning and switching to $GNUTLS_BRANCH..."
    make clean || true
    git fetch --all
    git checkout "$GNUTLS_BRANCH" 2>/dev/null || git checkout -b "$GNUTLS_BRANCH" "origin/$GNUTLS_BRANCH"
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

    if [ "$GNUTLS_BRANCH" == "gnutls-wolfssl-3.8.11" ]; then
        # Download nettle 3.10, since gnutls 3.8.11 requires nettle to be >= 3.10
        echo "Installing nettle 3.10 to $NETTLE_INSTALL..."

        wget https://ftp.gnu.org/gnu/nettle/nettle-3.10.tar.gz
        tar -xzf nettle-3.10.tar.gz
        cd nettle-3.10

        # Build and install
        ./configure --prefix=$NETTLE_INSTALL
        make -j$(nproc)
        sudo make install

        # Update library cache
        sudo ldconfig

        export PKG_CONFIG_PATH="$NETTLE_INSTALL/lib64/pkgconfig:$NETTLE_INSTALL/lib/pkgconfig:$PKG_CONFIG_PATH"
        export LD_LIBRARY_PATH="$NETTLE_INSTALL/lib64:$NETTLE_INSTALL/lib:$LD_LIBRARY_PATH"
        export LDFLAGS="-L$NETTLE_INSTALL/lib64 -L$NETTLE_INSTALL/lib -Wl,-rpath,$NETTLE_INSTALL/lib64 -Wl,-rpath,$NETTLE_INSTALL/lib"

        cd ../
    fi

    ./configure $CONFIG_OPTS 'CFLAGS=-DGNUTLS_WOLFSSL'

    export GNUTLS_FORCE_FIPS_MODE=1

    make -j9
fi

sudo make install
cd ../

cd ./wolfssl-gnutls-wrapper
make
sudo make install PROVIDER_PATH="$PROVIDER_PATH" GNUTLS_INSTALL="$GNUTLS_INSTALL" WOLFSSL_INSTALL="$WOLFSSL_INSTALL"
cd ../

echo ""
echo "=============================================="
echo "Build completed successfully!"
echo "=============================================="
echo "  FIPS Mode:        $([ $FIPS_MODE -eq 1 ] && echo 'ENABLED' || echo 'DISABLED')"
echo "  GnuTLS Branch:    $GNUTLS_BRANCH"
echo "  wolfSSL:          $WOLFSSL_INSTALL"
echo "  GnuTLS:           $GNUTLS_INSTALL"
echo "  Provider:         $PROVIDER_PATH"
if [ "$GNUTLS_BRANCH" == "gnutls-wolfssl-3.8.11" ]; then
    echo "  Nettle:           $NETTLE_INSTALL"
fi
echo "=============================================="
