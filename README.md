# gnutls-wolfssl

Experimental port of wolfSSL into GnuTLS. One script builds everything and drops the bits under /opt.

## Quick start
```
git clone https://github.com/YOURORG/gnutls-wolfssl.git
cd gnutls-wolfssl
# regular build
./setup.sh

# build with FIPS 140 support
./setup.sh fips
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
| GNUTLS_FORCE_FIPS_MODE | – | set at runtime to enforce FIPS |

## Directory layout (after setup.sh has been run)
```
setup.sh                       do‑it‑all build script
rebuild-gnutls.sh              rebuild GnuTLS only
wolfssl/                       upstream clone
gnutls/                        upstream clone + branch gnutls-wolfssl
wolfssl-gnutls-wrapper/        thin shim + tests
```

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
