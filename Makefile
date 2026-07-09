# ══════════════════════════════════════════════════════════════════
#  Project Aegis — Makefile
#  Zero-Trust USB Security Suite
# ══════════════════════════════════════════════════════════════════

.PHONY: all build build-release build-ui run-daemon run test clean install uninstall package help

# ── Variables ──────────────────────────────────────────────────────
DAEMON_BIN     := target/release/aegis-daemon
DAEMON_BIN_DEV := target/debug/aegis-daemon
UI_DIR         := aegis-ui
CARGO          := cargo
NPM            := npm

# Colours
GREEN  := \033[0;32m
YELLOW := \033[1;33m
BLUE   := \033[0;34m
NC     := \033[0m

help: ## Show this help message
	@echo ""
	@echo "  Project Aegis — Build System"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "  Usage: make \033[0;34m<target>\033[0m\n\n  Targets:\n"} \
	      /^[a-zA-Z_-]+:.*?##/ { printf "    \033[0;34m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""

all: build ## Default: build everything in debug mode

# ── Rust Backend ───────────────────────────────────────────────────

build: ## Build all Rust crates (debug)
	@echo "$(BLUE)=> Building Rust workspace (debug)...$(NC)"
	$(CARGO) build
	@echo "$(GREEN)=> Build complete.$(NC)"

build-release: ## Build all Rust crates (release, optimised)
	@echo "$(BLUE)=> Building Rust workspace (release)...$(NC)"
	$(CARGO) build --release
	@echo "$(GREEN)=> Release build complete: $(DAEMON_BIN)$(NC)"

build-daemon: ## Build only the daemon (release)
	$(CARGO) build -p aegis-daemon --release

# ── Frontend ────────────────────────────────────────────────────────

build-ui: ## Build the Tauri desktop app (production bundle)
	@echo "$(BLUE)=> Building Tauri UI bundle...$(NC)"
	cd $(UI_DIR) && $(NPM) install && $(NPM) run tauri build
	@echo "$(GREEN)=> Tauri bundle complete.$(NC)"

# ── Running ─────────────────────────────────────────────────────────

run-daemon: ## Run the daemon in development mode (foreground)
	@echo "$(BLUE)=> Starting Aegis daemon (dev mode)...$(NC)"
	@rm -f /tmp/aegis.sock
	RUST_LOG=debug $(CARGO) run -p aegis-daemon

run: ## Run the full stack (daemon + Tauri UI) — same as start.sh
	@bash start.sh

# ── Testing ─────────────────────────────────────────────────────────

test: ## Run all unit tests across the workspace
	@echo "$(BLUE)=> Running workspace tests...$(NC)"
	$(CARGO) test --workspace -- --nocapture
	@echo "$(GREEN)=> All tests passed.$(NC)"

test-verbose: ## Run tests with verbose output
	$(CARGO) test --workspace -- --nocapture --test-threads=1

# ── Installation ────────────────────────────────────────────────────

install: build-release ## Build and install daemon system-wide (requires sudo)
	@echo "$(YELLOW)=> Installing (requires root)...$(NC)"
	sudo bash install/install.sh

uninstall: ## Uninstall the daemon and service
	sudo bash install/install.sh --uninstall

# ── Packaging ────────────────────────────────────────────────────────

package-deb: build-release build-ui ## Build a .deb package (requires cargo-deb)
	@echo "$(BLUE)=> Packaging .deb...$(NC)"
	@which cargo-deb > /dev/null || (echo "Installing cargo-deb..." && cargo install cargo-deb)
	$(CARGO) deb -p aegis-daemon
	@echo "$(GREEN)=> .deb package built in target/debian/$(NC)"

# ── Utility ──────────────────────────────────────────────────────────

clean: ## Clean all build artefacts
	$(CARGO) clean
	rm -rf $(UI_DIR)/dist $(UI_DIR)/node_modules

fmt: ## Format all Rust code
	$(CARGO) fmt --all

lint: ## Run Clippy linter on all crates
	$(CARGO) clippy --workspace -- -D warnings

check: ## Run cargo check (fast type-check without building)
	$(CARGO) check --workspace

audit: ## Run cargo-audit to check for known vulnerabilities
	@which cargo-audit > /dev/null || cargo install cargo-audit
	cargo audit
