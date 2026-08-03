CC ?= cc
CPPFLAGS := -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Iinclude
CFLAGS := -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
LDLIBS := -lncursesw

BUILD_DIR := build
TARGET := $(BUILD_DIR)/free_proxy
TEST_TARGET := $(BUILD_DIR)/free_proxy_tests
SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:src/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean install uninstall test

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $^ $(LDLIBS) -o $@

$(TEST_TARGET): tests/test_unit.c src/config.c src/socks5.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

test: $(TEST_TARGET)
	$(TEST_TARGET)

install: $(TARGET)
	install -Dm755 $(TARGET) /usr/local/bin/free_proxy
	install -Dm644 systemd/free_proxy.service /etc/systemd/system/free_proxy.service
	systemctl daemon-reload

uninstall:
	-/usr/local/bin/free_proxy uninstall --yes
	-systemctl disable --now free_proxy.service
	rm -rf /etc/free_proxy /run/free_proxy
	rm -f /etc/systemd/system/free_proxy.service /usr/local/bin/free_proxy
	systemctl daemon-reload

clean:
	rm -rf $(BUILD_DIR)
