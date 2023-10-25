TARGET=ncod
OS := $(shell uname)
LDFLAGS := $(LDFLAGS) $(shell pkg-config --libs libsodium)
CC ?= clang
INSTALL ?= install
CFLAGS ?= -Wall -Werror
CFLAGS := $(CFLAGS)  $(shell pkg-config --cflags libsodium)

ifeq ($(OS),Linux)
	CFLAGS := $(CFLAGS) -D LINUX
	LDFLAGS := $(LDFLAGS) -lbsd
	DESTDIR ?= /usr/bin
	MANDIR ?= /usr/share/man
else
	DESTDIR ?= /usr/local/bin
	MANDIR ?= /usr/share/man
endif
ifeq ($(OS),OpenBSD)
	CFLAGS := $(CFLAGS) -D OPENBSD
	MANDIR ?= /usr/local/man
endif


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
