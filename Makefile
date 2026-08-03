CC ?= cc
CPPFLAGS := -D_POSIX_C_SOURCE=200809L -Iinclude
CFLAGS := -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
LDLIBS := -lncursesw

BUILD_DIR := build
TARGET := $(BUILD_DIR)/free_proxy
SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:src/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean install uninstall

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $^ $(LDLIBS) -o $@

install: $(TARGET)
	install -Dm755 $(TARGET) /usr/local/bin/free_proxy
	install -Dm644 systemd/free_proxy.service /usr/local/lib/free_proxy/free_proxy.service

uninstall:
	rm -f /usr/local/bin/free_proxy /usr/local/lib/free_proxy/free_proxy.service

clean:
	rm -rf $(BUILD_DIR)
