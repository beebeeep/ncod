TARGET=ncod
OS := $(shell uname)
LDFLAGS := $(LDFLAGS) $(shell pkg-config --libs libsodium)
CC ?= clang
CFLAGS ?= -Wall -Werror
CFLAGS := $(CFLAGS)  $(shell pkg-config --cflags libsodium)

ifeq ($(OS),Linux)
	CFLAGS := $(CFLAGS) -D LINUX
endif

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

.PHONY: default all clean

default: $(TARGET)

all: default

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
