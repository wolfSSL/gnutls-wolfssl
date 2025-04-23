TESTS = test_sha256 test_aescbc test_aesgcm test_hmac test_ecdsa_sign_and_verify test_rsa_sign_and_verify test_ecdh_encrypt_and_decrypt test_eddsa_sign_and_verify

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    INCLUDES = -I/opt/gnutls/include/ -I/opt/gnutls/include/gnutls/
else
    INCLUDES = -I/opt/gnutls/include/gnutls/
endif

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

test_sha256: test_sha256.c
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_aescbc: test_aescbc.c
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_aesgcm: test_aesgcm.c
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_hmac: test_hmac.c
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_ecdsa: test_ecdsa.c
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_ecdsa_sign_and_verify: test_ecdsa_sign_and_verify.c
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_eddsa_sign_and_verify: test_eddsa_sign_and_verify.c
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_ecdh_encrypt_and_decrypt: test_ecdh_encrypt_and_decrypt.c
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_rsa_sign_and_verify: test_rsa_sign_and_verify.c
	$(CC) -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

run-%:
	GNUTLS_DEBUG_LEVEL=9 ./$*

run: $(TESTS)
	@passed=0; failed=0; failed_tests=""; \
	for test in $(TESTS); do \
		echo "\n>> Running $$test..."; \
		if GNUTLS_DEBUG_LEVEL=9 ./$$test; then \
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

clean:
	rm -f $(TESTS)
	rm -rf *.dSYM

.PHONY += run run-verbose
