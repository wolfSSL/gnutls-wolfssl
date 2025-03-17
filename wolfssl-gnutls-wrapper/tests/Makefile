TESTS = test_sha256 test_aescbc test_aesgcm test_hmac

INCLUDES = -I/opt/gnutls/include/gnutls/
LDFLAGS = -L/opt/gnutls/lib -Wl,-rpath,/opt/gnutls/lib -Wl,--no-as-needed -Wl,-z,now
LIBS = -lgnutls -ldl

all: $(TESTS)

test_sha256: test_sha256.c
	gcc -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_aescbc: test_aescbc.c
	gcc -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_aesgcm: test_aesgcm.c
	gcc -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

test_hmac: test_hmac.c
	gcc -g -o $@ $< $(INCLUDES) $(LDFLAGS) $(LIBS)

run-%:
	 GNUTLS_DEBUG_LEVEL=9 ./$*

clean:
	rm -f $(TESTS)

.PHONY = all clean $(addprefix run-,$(TESTS))
