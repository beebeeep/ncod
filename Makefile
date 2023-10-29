TARGET=ncod

CC ?= clang
INSTALL ?= install
CFLAGS ?= -Wall -Werror
FZF_CMD ?= fzf
OS := $(shell uname)



ifeq ($(DEBUG),on)
	CFLAGS := $(CFLAGS) -g -D DEBUG
	CLIPBOARD_CMD := cat
endif

ifeq ($(OS),Linux)
	PKGCONFIG := pkg-config
	CLIPBOARD_CMD ?= xclip
	CFLAGS := $(CFLAGS) -D LINUX
	LDFLAGS := $(LDFLAGS) -lbsd
	DESTDIR ?= /usr/bin
	MANDIR ?= /usr/share/man
else ifeq ($(OS),OpenBSD)
	PKGCONFIG := pkg-config
	CLIPBOARD_CMD ?= xclip
	CFLAGS := $(CFLAGS) -D BSD
	DESTDIR ?= /usr/local/bin
	MANDIR ?= /usr/local/man
else ifeq ($(OS),FreeBSD)
	PKGCONFIG := pkgconf
	CLIPBOARD_CMD ?= xclip
	CFLAGS := $(CFLAGS) -D BSD
	DESTDIR ?= /usr/local/bin
	MANDIR ?= /usr/local/man
else ifeq ($(OS),Darwin)
	PKGCONFIG := pkg-config
	CLIPBOARD_CMD ?= pbcopy
	DESTDIR ?= /usr/local/bin
	MANDIR ?= /usr/local/share/man
else
	DESTDIR ?= /usr/local/bin
	MANDIR ?= /usr/share/man
endif

CFLAGS := $(CFLAGS)  $(shell $(PKGCONFIG) --cflags libsodium) -D CLIPBOARD_CMD='"$(CLIPBOARD_CMD)"' -D FZF_CMD='"$(FZF_CMD)"'
LDFLAGS := $(LDFLAGS) $(shell $(PKGCONFIG) --libs libsodium)


OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

.PHONY: default all clean install

default: $(TARGET)

all: default

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

install: $(TARGET)
	$(INSTALL) -m 0555 ncod $(DESTDIR)/ncod
	$(INSTALL) -D -m 0555 ncod.1 $(MANDIR)/man1/ncod.1


clean:
	-rm -f *.o
	-rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
