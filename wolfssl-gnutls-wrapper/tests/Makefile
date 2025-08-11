TESTS = test_hash test_long_hash test_shake test_aescbc test_aescfb8 test_aesgcm test_aesccm test_aesxts test_hmac test_cmac test_gmac test_rnd test_rnd_fork test_tls_prf test_hkdf test_pbkdf2 test_ecdsa_sign_and_verify test_ecdh_encrypt_and_decrypt test_eddsa_sign_and_verify test_rsa_sign_and_verify test_rsa_encrypt_and_decrypt test_dh_encrypt_and_decrypt test_pk_import_export test_long_hash test_fips

PKGCONF ?= pkg-config
UNAME_S := $(shell uname -s)

# Defaults; can be overridden by environment
GNUTLS_PREFIX  := $(if $(GNUTLS_INSTALL),$(GNUTLS_INSTALL),/opt/gnutls)
PROVIDER_PATH  := $(if $(PROVIDER_PATH),$(PROVIDER_PATH),/opt/wolfssl-gnutls-wrapper)

# Make pkg-config see a custom /opt gnutls, if present
export PKG_CONFIG_PATH := $(GNUTLS_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)

# Detect pkg-config availability of gnutls
HAVE_PC_GNUTLS := $(shell $(PKGCONF) --exists gnutls && echo yes || echo no)

ifeq ($(HAVE_PC_GNUTLS),yes)
  GNUTLS_CFLAGS := $(shell $(PKGCONF) --cflags gnutls)
  GNUTLS_LIBS   := $(shell $(PKGCONF) --libs   gnutls)
  GNUTLS_LIBDIR := $(shell $(PKGCONF) --variable=libdir gnutls)
else
  GNUTLS_CFLAGS := -I$(GNUTLS_PREFIX)/include -I$(GNUTLS_PREFIX)/include/gnutls
  GNUTLS_LIBS   := -L$(GNUTLS_PREFIX)/lib -lgnutls
  GNUTLS_LIBDIR := $(GNUTLS_PREFIX)/lib
endif

PROVIDER_LIBDIR := $(PROVIDER_PATH)/lib

# Compiler
ifeq ($(UNAME_S),Darwin)
  CC = clang
else
  CC = gcc
endif

# Includes
INCLUDES = $(GNUTLS_CFLAGS)

# Linker flags + rpaths to BOTH gnutls and provider
ifeq ($(UNAME_S),Linux)
  LDFLAGS = -Wl,--no-as-needed -Wl,-z,now \
            -Wl,-rpath,$(GNUTLS_LIBDIR) -Wl,-rpath,$(PROVIDER_LIBDIR) \
            -L$(GNUTLS_LIBDIR)
endif
ifeq ($(UNAME_S),Darwin)
  LDFLAGS = -Wl,-rpath,$(GNUTLS_LIBDIR) -Wl,-rpath,$(PROVIDER_LIBDIR) \
            -L$(GNUTLS_LIBDIR)
endif

# Libraries (dl only on Linux)
ifeq ($(UNAME_S),Linux)
  LIBS = $(GNUTLS_LIBS) -ldl
else
  LIBS = $(GNUTLS_LIBS)
endif

all: $(TESTS)

%: %.c test_util.h
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

run-%:
	GNUTLS_DEBUG_LEVEL=9 LD_LIBRARY_PATH="$(GNUTLS_LIBDIR):$(PROVIDER_LIBDIR):$$LD_LIBRARY_PATH" DYLD_LIBRARY_PATH="$(GNUTLS_LIBDIR):$(PROVIDER_LIBDIR):$$DYLD_LIBRARY_PATH" ./$*

run: $(TESTS)
	@passed=0; failed=0; failed_tests=""; \
	for test in $(TESTS); do \
		echo "\n>> Running $$test..."; \
		if GNUTLS_DEBUG_LEVEL=9 LD_LIBRARY_PATH="$(GNUTLS_LIBDIR):$(PROVIDER_LIBDIR):$$LD_LIBRARY_PATH" DYLD_LIBRARY_PATH="$(GNUTLS_LIBDIR):$(PROVIDER_LIBDIR):$$DYLD_LIBRARY_PATH" $(VALGRIND) ./$$test $(CMD_LINE_ARG); then \
			echo "\n✅ $$test PASSED"; \
			passed=$$((passed+1)); \
		else \
			echo "\n❌ $$test FAILED"; \
			failed=$$((failed+1)); \
			failed_tests="$$failed_tests $$test"; \
		fi; \
	done; \
	echo "\n=== Test Summary ==="; \
	echo "Total tests:  $$((passed+failed))"; \
	echo "Passed:       $$passed"; \
	echo "Failed:       $$failed"; \
	if [ $$failed -gt 0 ]; then \
		echo "\nFailed tests:$$failed_tests"; \
		exit 1; \
	else \
		echo "\nAll tests passed! 🎉"; \
	fi

run_fast:
	CMD_LINE_ARG="-fast" $(MAKE) run

run_valgrind:
	VALGRIND=valgrind $(MAKE) run_fast

run_fips: $(TESTS)
	GNUTLS_FORCE_FIPS_MODE=1 $(MAKE) run

run_gnutls: $(TESTS)
	GNUTLS_NO_PROVIDER=1 $(MAKE) run

run_fast_gnutls: $(TESTS)
	GNUTLS_NO_PROVIDER=1 $(MAKE) run_fast

run_valgrind_gnutls: $(TESTS)
	GNUTLS_NO_PROVIDER=1 $(MAKE) run_valgrind

clean:
	rm -f $(TESTS)
	rm -rf *.dSYM

.PHONY += all run run-% run_fast run_valgrind run_fips run_gnutls run_fast_gnutls run_valgrind_gnutls clean
