PKGCONF ?= pkg-config
CC ?= gcc

# Prefixes used when pkg-config isn't available
GNUTLS_PREFIX := $(if $(GNUTLS_INSTALL),$(GNUTLS_INSTALL),/opt/gnutls)
WOLFSSL_PREFIX := $(if $(WOLFSSL_INSTALL),$(WOLFSSL_INSTALL),/opt/wolfssl)

# Use a dedicated pkg-config path ONLY for GnuTLS detection (no global lookup)
GNUTLS_PKGCONF := PKG_CONFIG_PATH=$(GNUTLS_PREFIX)/lib/pkgconfig $(PKGCONF)

# Detect availability of pkg-config .pc files
HAVE_PC_WOLFSSL := $(shell $(PKGCONF) --exists wolfssl && echo yes || echo no)
# Only check under GNUTLS_PREFIX; do NOT use global gnutls
HAVE_PC_GNUTLS  := $(shell $(GNUTLS_PKGCONF) --exists gnutls && echo yes || echo no)

# Flags from pkg-config (prefer), otherwise fall back to /opt/* paths
ifeq ($(HAVE_PC_WOLFSSL),yes)
  WOLFSSL_CFLAGS := $(shell $(PKGCONF) --cflags wolfssl)
  WOLFSSL_LIBS   := $(shell $(PKGCONF) --libs   wolfssl)
  WOLFSSL_LIBDIR := $(shell $(PKGCONF) --variable=libdir wolfssl)
else
  WOLFSSL_CFLAGS := -I$(WOLFSSL_PREFIX)/include
  WOLFSSL_LIBS   := -L$(WOLFSSL_PREFIX)/lib -lwolfssl
  WOLFSSL_LIBDIR := $(WOLFSSL_PREFIX)/lib
endif

ifeq ($(HAVE_PC_GNUTLS),yes)
  GNUTLS_CFLAGS := $(shell $(GNUTLS_PKGCONF) --cflags gnutls)
  GNUTLS_LIBS   := $(shell $(GNUTLS_PKGCONF) --libs   gnutls)
  GNUTLS_LIBDIR := $(shell $(GNUTLS_PKGCONF) --variable=libdir gnutls)
else
  GNUTLS_CFLAGS := -I$(GNUTLS_PREFIX)/include
  GNUTLS_LIBS   := -L$(GNUTLS_PREFIX)/lib -lgnutls
  GNUTLS_LIBDIR := $(GNUTLS_PREFIX)/lib
endif

# Include dirs (now come from pkg-config when available)
INCLUDES := $(GNUTLS_CFLAGS) $(WOLFSSL_CFLAGS)

# Default to /opt/wolfssl-gnutls-wrapper when the user hasn’t supplied PROVIDER_PATH
ifndef PROVIDER_PATH
PROVIDER_PATH := /opt/wolfssl-gnutls-wrapper
endif

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
  CFLAGS       += -DENABLE_WOLFSSL -fPIC -Wall -Wextra
  CFLAGS_DEBUG += -g
  # Use rpath to wherever we actually link from
  LDFLAGS      += -Wl,--no-as-needed -Wl,-z,now \
                  -Wl,-rpath,$(GNUTLS_LIBDIR) -Wl,-rpath,$(WOLFSSL_LIBDIR)
  SOFLAG := -shared
  DL_LIBS := -ldl
endif

ifeq ($(UNAME_S),Darwin)
  CC           := clang
  CFLAGS       += -DENABLE_WOLFSSL -fPIC -Wall -Wextra
  CFLAGS_DEBUG += -g
  LDFLAGS      += -Wl,-rpath,$(GNUTLS_LIBDIR) -Wl,-rpath,$(WOLFSSL_LIBDIR)
  SOFLAG := -dynamiclib
  DL_LIBS :=
endif

# Link libs: prefer pkg-config expansion; fallback already includes -l flags
LIBS := $(GNUTLS_LIBS) $(WOLFSSL_LIBS) $(DL_LIBS)

WRAPPER_TARGET := libgnutls-wolfssl-wrapper.so
WRAPPER_SRCS   := $(wildcard src/*.c)
WRAPPER_OBJS   := $(WRAPPER_SRCS:.c=.o)

all: $(WRAPPER_TARGET)

$(WRAPPER_TARGET): $(WRAPPER_OBJS)
	$(CC) $(SOFLAG) $(LDFLAGS) -o $@ $(WRAPPER_OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

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
	rm -f $(WRAPPER_TARGET) $(WRAPPER_OBJS)

