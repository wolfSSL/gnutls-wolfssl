CC = gcc
INCLUDES = -I/opt/gnutls/include/ -I/opt/wolfssl/include/

# Default to /opt/wolfssl-gnutls-wrapper when the user hasn’t supplied PROVIDER_PATH
ifndef PROVIDER_PATH
PROVIDER_PATH := /opt/wolfssl-gnutls-wrapper
endif

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
	CFLAGS       = -DENABLE_WOLFSSL -fPIC -Wall -Wextra -Werror
	CFLAGS_DEBUG = -DENABLE_WOLFSSL -fPIC -Wall -Wextra -Werror -g
	LDFLAGS      = -shared -L/opt/gnutls/lib -L/opt/wolfssl/lib -Wl,-rpath,/opt/wolfssl/lib -Wl,--no-as-needed -Wl,-z,now
endif

ifeq ($(UNAME_S),Darwin)
	CC           = clang
	CFLAGS       = -DENABLE_WOLFSSL -fPIC -Wall -Wextra
	CFLAGS_DEBUG = -DENABLE_WOLFSSL -fPIC -Wall -Wextra -g
	LDFLAGS      = -shared -L/opt/gnutls/lib -L/opt/wolfssl/lib -Wl,-rpath,/opt/wolfssl/lib
endif

LIBS = -lgnutls -lwolfssl -ldl

WRAPPER_TARGET = libgnutls-wolfssl-wrapper.so
WRAPPER_SRCS   = src/wolfssl.c
WRAPPER_HDRS   = src/gnutls_compat.h src/wolfssl.h

all: $(WRAPPER_TARGET)

$(WRAPPER_TARGET): $(WRAPPER_SRCS) $(WRAPPER_HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) $(WRAPPER_SRCS) -o $@ $(LDFLAGS) $(LIBS)

install:
	mkdir -p $(PROVIDER_PATH)/lib
	install -m 755 $(WRAPPER_TARGET) $(PROVIDER_PATH)/lib/

test:
	(cd tests; make run)

test_fast:
	(cd tests; make run_fast)

test_fips:
	(cd tests; make run_fips)

clean:
	rm -f $(WRAPPER_TARGET)
