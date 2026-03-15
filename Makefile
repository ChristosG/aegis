PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
SYSCONFDIR = /etc/aegis
SERVICEDIR = /etc/systemd/system

VERSION = $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

.PHONY: build release release-full install install-full uninstall test test-web lint fmt clean

build:
	cargo build

release:
	cargo build --release

release-full:
	cargo build --release --features web-dashboard

test:
	cargo test

test-web:
	cargo test --features web-dashboard

lint:
	cargo clippy -- -D warnings
	cargo clippy --features web-dashboard -- -D warnings

fmt:
	cargo fmt --check

install: release
	install -Dm755 target/release/aegis $(DESTDIR)$(BINDIR)/aegis
	install -Dm644 aegis.service $(DESTDIR)$(SERVICEDIR)/aegis.service
	install -dm755 $(DESTDIR)$(SYSCONFDIR)
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/aegis.toml ]; then \
		install -Dm644 aegis.toml $(DESTDIR)$(SYSCONFDIR)/aegis.toml; \
		echo "Installed default config to $(SYSCONFDIR)/aegis.toml"; \
	else \
		echo "Config $(SYSCONFDIR)/aegis.toml already exists, not overwriting"; \
	fi
	@echo ""
	@echo "Aegis $(VERSION) installed successfully. (CLI-only)"
	@echo "  Binary:  $(BINDIR)/aegis"
	@echo "  Config:  $(SYSCONFDIR)/aegis.toml"
	@echo "  Service: $(SERVICEDIR)/aegis.service"
	@echo ""
	@echo "Next steps:"
	@echo "  sudo aegis init"
	@echo "  sudo systemctl enable --now aegis"

install-full: release-full
	install -Dm755 target/release/aegis $(DESTDIR)$(BINDIR)/aegis
	install -Dm644 aegis.service $(DESTDIR)$(SERVICEDIR)/aegis.service
	install -dm755 $(DESTDIR)$(SYSCONFDIR)
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/aegis.toml ]; then \
		install -Dm644 aegis.toml $(DESTDIR)$(SYSCONFDIR)/aegis.toml; \
		echo "Installed default config to $(SYSCONFDIR)/aegis.toml"; \
	else \
		echo "Config $(SYSCONFDIR)/aegis.toml already exists, not overwriting"; \
	fi
	@echo ""
	@echo "Aegis $(VERSION) installed successfully. (Full — with web dashboard)"
	@echo "  Binary:  $(BINDIR)/aegis"
	@echo "  Config:  $(SYSCONFDIR)/aegis.toml"
	@echo "  Service: $(SERVICEDIR)/aegis.service"
	@echo ""
	@echo "Next steps:"
	@echo "  sudo aegis init"
	@echo "  sudo systemctl enable --now aegis"
	@echo "  Web dashboard: http://127.0.0.1:9443"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/aegis
	rm -f $(DESTDIR)$(SERVICEDIR)/aegis.service
	@echo "Binary and service removed. Config left at $(SYSCONFDIR)/"
	@echo "To fully remove: sudo rm -rf $(SYSCONFDIR) ~/.aegis"

clean:
	cargo clean
