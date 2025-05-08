TESTS = test_hash test_long_hash test_shake test_aescbc test_aescfb8 test_aesgcm test_aesccm test_aesxts test_hmac test_cmac test_gmac test_rnd test_rnd_fork test_tls_prf test_hkdf test_pbkdf2 test_ecdsa_sign_and_verify test_ecdh_encrypt_and_decrypt test_eddsa_sign_and_verify test_rsa_sign_and_verify test_rsa_encrypt_and_decrypt test_dh_encrypt_and_decrypt test_pk_import_export test_long_hash

UNAME_S := $(shell uname -s)
INCLUDES = -I/opt/gnutls/include/ -I/opt/gnutls/include/gnutls/

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    CC = clang
else
    CC = gcc
endif

ifeq ($(UNAME_S),Linux)
    LDFLAGS = -L/opt/gnutls/lib -Wl,-rpath,/opt/gnutls/lib -Wl,--no-as-needed -Wl,-z,now
endif

ifeq ($(UNAME_S),Darwin)
    LDFLAGS = -L/opt/gnutls/lib -Wl,-rpath,/opt/gnutls/lib
endif

LIBS = -lgnutls -ldl

all: $(TESTS)

%: %.c test_util.h
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

run-%:
	GNUTLS_DEBUG_LEVEL=9 ./$*

run: $(TESTS)
	@passed=0; failed=0; failed_tests=""; \
	for test in $(TESTS); do \
		echo "\n>> Running $$test..."; \
		if GNUTLS_DEBUG_LEVEL=9 $(VALGRIND) ./$$test $(CMD_LINE_ARG); then \
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
	CMD_LINE_ARG="-fast" make run

run_valgrind:
	VALGRIND=valgrind  make run_fast

run_fips: $(TESTS)
	GNUTLS_FORCE_FIPS_MODE=1 make run

run_gnutls: $(TESTS)
	GNUTLS_NO_PROVIDER=1 make run

run_fast_gnutls: $(TESTS)
	GNUTLS_NO_PROVIDER=1 make run_fast

run_fast_gnutls: $(TESTS)
	GNUTLS_NO_PROVIDER=1 make run_valgrind

clean:
	rm -f $(TESTS)
	rm -rf *.dSYM

.PHONY += run run-verbose
