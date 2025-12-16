# gnutls-wolfssl

Experimental port of wolfSSL into GnuTLS. One script builds everything and drops the bits under /opt.

## Quick start
```
git clone https://github.com/wolfssl/gnutls-wolfssl.git
cd gnutls-wolfssl
# regular build (uses default GnuTLS 3.8.9)
./setup.sh

# build with FIPS 140 support
./setup.sh fips

# build specific GnuTLS version
./setup.sh 3.8.11

# build specific version with FIPS 140 support
./setup.sh fips 3.8.11

# show help and all options
./setup.sh --help
```
On success you get:
```
/opt/wolfssl                  wolfSSL
/opt/gnutls                   GnuTLS built on wolfSSL
/opt/wolfssl-gnutls-wrapper   runtime shim
```
If the loader can’t find the libs, add the path to LD_LIBRARY_PATH (Linux) or DYLD_LIBRARY_PATH (macOS).

## Environment variables
| var | default | note |
|-----|---------|------|
| WOLFSSL_INSTALL | /opt/wolfssl | install prefix |
| GNUTLS_INSTALL  | /opt/gnutls  | install prefix |
| PROVIDER_PATH | /opt/wolfssl-gnutls-wrapper/ | install prefix|
| WOLFSSL_FIPS_BUNDLE | - | path to pre-downloaded wolfSSL FIPS bundle (optional, FIPS mode only) |
| GNUTLS_FORCE_FIPS_MODE | 0 | set to 1 at runtime to enforce FIPS |
| WGW_LOGGING | 1 |By default wolfssl-gnutls-wrapper will show logging information. Set to 0 to turn off logging |
| WGW_LOGFILE | - | By default wolfssl-gnutls-wrapper will log to stderr. This can be changed to stdout or a filename |


## Directory layout (after setup.sh has been run)
```
setup.sh                       do‑it‑all build script
rebuild-gnutls.sh              rebuild GnuTLS only
wolfssl/                       upstream clone
gnutls/                        upstream clone + branch gnutls-wolfssl-VERSION
wolfssl-gnutls-wrapper/        thin shim + tests
```

## Version support
The setup script supports building different GnuTLS versions by specifying the version number as an argument. The script will checkout the corresponding branch (e.g., `gnutls-wolfssl (3.8.9)`, `gnutls-wolfssl-3.8.11 (3.8.11)`).

**Note:** When building GnuTLS 3.8.11 on Linux, the script automatically downloads and builds nettle 3.10, as this version requires nettle >= 3.10.

## Tests
```
cd wolfssl-gnutls-wrapper

# build wrapper
make

# full suite
make test

# fast run of the test suite
make test_fast

# test fips (only if ./setup.sh was run in fips mode)
make test_fips
```
Each test prints ✔️/❌ and a summary.

## Using in your project
```
cc app.c \
  -I/opt/gnutls/include -I/opt/wolfssl/include \
  -L/opt/gnutls/lib -lgnutls \
  -L/opt/wolfssl/lib -lwolfssl \
  -L/opt/wolfssl-gnutls-wrapper/lib -lgnutls-wolfssl-wrapper
```
Make sure the wrapper comes after gnutls on the linker line.

## Clean up
```
sudo rm -rf /opt/wolfssl /opt/gnutls /opt/wolfssl-gnutls-wrapper
```
