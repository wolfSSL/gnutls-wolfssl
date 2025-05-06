CC = gcc
CFLAGS = -DENABLE_WOLFSSL -fPIC -Wall -Wextra
CFLAGS_DEBUG = -DENABLE_WOLFSSL -fPIC -Wall -Wextra -g
INCLUDES = -I/opt/gnutls/include/ -I/opt/wolfssl/include/

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    LDFLAGS = -shared -L/opt/gnutls/lib -L/opt/wolfssl/lib -Wl,-rpath,/opt/wolfssl/lib -Wl,--no-as-needed -Wl,-z,now
endif

ifeq ($(UNAME_S),Darwin)
    CC = clang
    LDFLAGS = -shared -L/opt/gnutls/lib -L/opt/wolfssl/lib -Wl,-rpath,/opt/wolfssl/lib
endif

LIBS = -lgnutls -lwolfssl -ldl

WRAPPER_TARGET = libgnutls-wolfssl-wrapper.so
WRAPPER_SRCS = src/wolfssl.c
WRAPPER_HDRS = src/gnutls_compat.h src/wolfssl.h

all: $(WRAPPER_TARGET)

$(WRAPPER_TARGET): $(WRAPPER_SRCS) $(WRAPPER_HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) $(WRAPPER_SRCS) -o $@ $(LDFLAGS) $(LIBS)

install:
	mkdir -p /opt/wolfssl-gnutls-wrapper/lib/
	install -m 755 $(WRAPPER_TARGET) /opt/wolfssl-gnutls-wrapper/lib/

test:
	(cd tests; make run)

clean:
	rm -f $(WRAPPER_TARGET)
