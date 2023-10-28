TARGET=ncod

CC ?= clang
INSTALL ?= install
CFLAGS ?= -Wall -Werror
FZF_CMD ?= fzf

CFLAGS := $(CFLAGS)  $(shell pkg-config --cflags libsodium)
LDFLAGS := $(LDFLAGS) $(shell pkg-config --libs libsodium)

ifeq ($(DEBUG),on)
	CFLAGS := $(CFLAGS) -g -D DEBUG
	CLIPBOARD_CMD := cat
endif

OS := $(shell uname)
ifeq ($(OS),Linux)
	CLIPBOARD_CMD ?= xclip
	CFLAGS := $(CFLAGS) -D LINUX
	LDFLAGS := $(LDFLAGS) -lbsd
	DESTDIR ?= /usr/bin
	MANDIR ?= /usr/share/man
else ifeq ($(OS),OpenBSD)
	CLIPBOARD_CMD ?= xclip
	CFLAGS := $(CFLAGS) -D OPENBSD
	DESTDIR ?= /usr/local/bin
	MANDIR ?= /usr/local/man
else ifeq ($(OS),Darwin)
	CLIPBOARD_CMD ?= pbcopy
	DESTDIR ?= /usr/local/bin
	MANDIR ?= /usr/share/man
else
	DESTDIR ?= /usr/local/bin
	MANDIR ?= /usr/share/man
endif

CFLAGS := $(CFLAGS) -D CLIPBOARD_CMD='"$(CLIPBOARD_CMD)"' -D FZF_CMD='"$(FZF_CMD)"'

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
	$(INSTALL) -m 0555 ncod.1 $(MANDIR)/man1/ncod.1


clean:
	-rm -f *.o
	-rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
