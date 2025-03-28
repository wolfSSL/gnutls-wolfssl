CC = gcc
CFLAGS = -DHAVE_ED25519 -DENABLE_WOLFSSL -fPIC -Wall -Wextra
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

all: $(WRAPPER_TARGET)

$(WRAPPER_TARGET): $(WRAPPER_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) $(WRAPPER_SRCS) -o $@ $(LDFLAGS) $(LIBS)

install:
	mkdir -p /opt/wolfssl-gnutls-wrapper/lib/
	install -m 755 $(WRAPPER_TARGET) /opt/wolfssl-gnutls-wrapper/lib/

clean:
	rm -f $(WRAPPER_TARGET)
