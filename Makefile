TARGET=ncod
LDFLAGS := $(LDFLAGS) $(shell pkg-config --libs libsodium)
CC=clang
LD=clang
CFLAGS ?= -Wall -Werror
CFLAGS := $(CFLAGS)  $(shell pkg-config --cflags libsodium)

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

.PHONY: default all clean

default: $(TARGET)

all: default

%.o: %.c $(HEADERS)
	$(LD) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
