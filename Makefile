CC ?= cc
CPPFLAGS := -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Iinclude
CFLAGS := -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
LDLIBS := -lncursesw -lpthread

APT_GET ?= apt-get
AUTO_INSTALL_DEPS ?= 1

BUILD_DIR := build
TARGET := $(BUILD_DIR)/free_proxy
TEST_TARGET := $(BUILD_DIR)/free_proxy_tests
SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:src/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean dependencies install uninstall test

all: $(TARGET)

# Check capabilities instead of package state so compatible packages also count.
# GNU make itself is the only prerequisite that cannot be bootstrapped here.
dependencies:
	@set -eu; \
	compiler='$(firstword $(CC))'; \
	missing_packages=''; \
	if ! command -v "$$compiler" >/dev/null 2>&1; then \
		case "$$compiler" in \
			cc|gcc) missing_packages="$$missing_packages build-essential" ;; \
			clang) missing_packages="$$missing_packages clang" ;; \
			*) echo "error: compiler '$$compiler' is missing and its apt package is unknown" >&2; exit 2 ;; \
		esac; \
		missing_packages="$$missing_packages libncurses-dev"; \
	elif ! printf '%s\n' '#include <ncursesw/ncurses.h>' \
		'int main(void) { initscr(); endwin(); return 0; }' | \
		$(CC) -x c - -o /dev/null -lncursesw -lpthread >/dev/null 2>&1; then \
		missing_packages="$$missing_packages libncurses-dev"; \
	fi; \
	if ! command -v iptables >/dev/null 2>&1 && \
		[ ! -x /usr/sbin/iptables ] && [ ! -x /sbin/iptables ] && \
		[ ! -x /usr/sbin/iptables-nft ] && [ ! -x /sbin/iptables-nft ]; then \
		missing_packages="$$missing_packages iptables"; \
	fi; \
	if [ -z "$$missing_packages" ]; then \
		echo "Dependencies are satisfied."; \
		exit 0; \
	fi; \
	echo "Missing apt packages:$$missing_packages"; \
	if [ "$(AUTO_INSTALL_DEPS)" != "1" ]; then \
		echo "Automatic installation is disabled (AUTO_INSTALL_DEPS=$(AUTO_INSTALL_DEPS))." >&2; \
		echo "Install manually: sudo $(APT_GET) update && sudo $(APT_GET) install$$missing_packages" >&2; \
		exit 2; \
	fi; \
	if ! command -v $(APT_GET) >/dev/null 2>&1; then \
		echo "error: apt-get is unavailable; install these packages with your system package manager:$$missing_packages" >&2; \
		exit 2; \
	fi; \
	if [ "$$(id -u)" -eq 0 ]; then \
		elevate=''; \
	elif command -v sudo >/dev/null 2>&1; then \
		elevate='sudo'; \
	else \
		echo "error: root privileges are required, but sudo is unavailable" >&2; \
		echo "Install manually as root: $(APT_GET) update && $(APT_GET) install$$missing_packages" >&2; \
		exit 2; \
	fi; \
	echo "Installing missing dependencies..."; \
	$$elevate $(APT_GET) update; \
	$$elevate $(APT_GET) install -y $$missing_packages

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: src/%.c | dependencies $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $^ $(LDLIBS) -o $@

$(TEST_TARGET): tests/test_unit.c src/config.c src/socks5.c | dependencies $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

test: $(TEST_TARGET)
	$(TEST_TARGET)

install: $(TARGET)
	install -Dm755 $(TARGET) /usr/local/bin/free_proxy
	install -Dm644 systemd/free_proxy.service /etc/systemd/system/free_proxy.service
	-systemctl daemon-reload

uninstall:
	-/usr/local/bin/free_proxy uninstall --yes
	-systemctl disable --now free_proxy.service
	rm -rf /etc/free_proxy /run/free_proxy
	rm -f /etc/systemd/system/free_proxy.service /usr/local/bin/free_proxy
	-systemctl daemon-reload
	@ss -lntp 2>/dev/null | grep -q ':12345 ' && echo "warning: port 12345 still in use" || true
	@iptables -t nat -S 2>/dev/null | grep -q FPROXY && echo "warning: FPROXY iptables rules still present" || true

clean:
	rm -rf $(BUILD_DIR)
