PROJECT_NAME  := entpassgen
SHELL         := bash
BENCHTIME     := 30s
FUZZTIME      := 30s
OUTPUT_DIR    := bin
OUTPUTS_DIR   := outputs
COVER_OUT     := $(OUTPUTS_DIR)/coverage.out
COVER_JSON    := $(OUTPUTS_DIR)/coverage.json
USER_BIN      := $(HOME)/bin
USER_BINARY   := $(USER_BIN)/$(PROJECT_NAME)
VERSION       := $(shell cat VERSION | tr -d '[:space:]')
BUILD_TIME    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
CGO_ENABLED   := 0
LDFLAGS       := -ldflags="-s -w -X 'main.buildVersion=$(VERSION)' -X 'main.buildTime=$(BUILD_TIME)'"
GCFLAGS       := -gcflags="-e"
GO_BUILD      := CGO_ENABLED=$(CGO_ENABLED) go build $(GCFLAGS) $(LDFLAGS) -trimpath -o
TARGETS := \
	darwin/amd64 \
	darwin/arm64 \
	linux/amd64 \
	linux/arm64 \
	windows/amd64

# ============================================================
# Help
# ============================================================

.PHONY: help
help:
	@echo "Makefile for $(PROJECT_NAME)"
	@echo
	@echo "Usage:"
	@echo "  make [target]"
	@echo
	@echo "Primary targets:"
	@echo "  ci          clean + vet + lint + unit + bench + fuzz + build"
	@echo "  build       Compile and write binary to $(OUTPUT_DIR)/"
	@echo "  install     Build then install to ~/bin/$(PROJECT_NAME)"
	@echo "  uninstall   Remove ~/bin/$(PROJECT_NAME) if it exists"
	@echo "  installed   Print 'yes' or 'no' — is $(PROJECT_NAME) reachable?"
	@echo "  clean       Remove $(OUTPUT_DIR)/ and $(OUTPUTS_DIR)/"
	@echo "  clean-all   clean + uninstall"
	@echo
	@echo "Test targets:"
	@echo "  unit        Run unit tests"
	@echo "  bench       Run benchmark tests"
	@echo "  fuzz        Run fuzz tests ($(FUZZTIME) each)"
	@echo "  coverage    Generate coverage report"
	@echo
	@echo "Quality targets:"
	@echo "  lint        Run gofmt"
	@echo "  vet         Run go vet"
	@echo "  prepare     go mod tidy + download + gofmt"
	@echo
	@echo "Release targets:"
	@echo "  all         Cross-compile for all target OS/Arch combinations"
	@echo "  run         Run the Go code directly (pass ARGS=... for flags)"
	@echo
	@echo "Target OS/Arch combinations:"
	@echo "  darwin/amd64  darwin/arm64"
	@echo "  linux/amd64   linux/arm64"
	@echo "  windows/amd64"

# ============================================================
# CI — full pipeline
# ============================================================

.PHONY: ci
ci: clean vet lint unit bench fuzz build
	@echo "CI pipeline complete."

# ============================================================
# Quality
# ============================================================

.PHONY: lint
lint:
	@echo "Running gofmt..."
	@UNFORMATTED=$$(/usr/bin/find . -type f -name '*.go' -exec gofmt -l {} \;); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "Unformatted files:"; \
		echo "$$UNFORMATTED"; \
		/usr/bin/find . -type f -name '*.go' -exec gofmt -w {} \;; \
		echo "Reformatted."; \
	else \
		echo "All files already formatted."; \
	fi

.PHONY: vet
vet:
	@echo "Running go vet..."
	@go vet ./...
	@echo "go vet passed."

# ============================================================
# Tests
# ============================================================

.PHONY: unit
unit: prepare
	@mkdir -p $(OUTPUTS_DIR)
	@echo "Running unit tests..."
	@go test -v -race -count=1 -timeout=120s ./... 2>&1 | tee $(OUTPUTS_DIR)/unit.log
	@go test -json -race -count=1 -timeout=120s ./... > $(OUTPUTS_DIR)/unit.json 2>/dev/null || true

.PHONY: bench
bench: prepare
	@echo "Running benchmarks (benchtime=$(BENCHTIME))..."
	@go test -bench=. -benchmem -benchtime=$(BENCHTIME) -run='^$$' ./...

.PHONY: fuzz
fuzz: prepare
	@echo "Fuzzing FuzzParseEntropy ($(FUZZTIME))..."
	@go test -run='^$$' -fuzz=FuzzParseEntropy -fuzztime=$(FUZZTIME) ./...
	@echo "Fuzzing FuzzGenerateRandomPassword ($(FUZZTIME))..."
	@go test -run='^$$' -fuzz=FuzzGenerateRandomPassword -fuzztime=$(FUZZTIME) ./...

.PHONY: coverage
coverage: prepare
	@mkdir -p $(OUTPUTS_DIR)
	@go test -coverprofile=$(COVER_OUT) ./...
	@go tool cover -func=$(COVER_OUT)
	@go tool cover -o $(COVER_JSON) -func=$(COVER_OUT)
	@COVERAGE=$$(go tool cover -func=$(COVER_OUT) | grep total | awk '{print $$3}' | tr -d '%'); \
	echo "Total coverage: $${COVERAGE}%"; \
	if awk "BEGIN { exit !($${COVERAGE} < 80.0) }"; then \
		echo "WARNING: coverage $${COVERAGE}% is below the 80% threshold."; \
	fi

# ============================================================
# Build
# ============================================================

.PHONY: prepare
prepare:
	@go mod tidy 1>/dev/null || echo "SKIPPED: go mod tidy"
	@go mod download 1>/dev/null || echo "SKIPPED: go mod download"
	@/usr/bin/find . -type f -name '*.go' -exec gofmt -w {} \; || echo "SKIPPED: gofmt"

.PHONY: build
build: prepare
	@mkdir -p $(OUTPUT_DIR)
	@echo "Building $(PROJECT_NAME)..."
	@$(GO_BUILD) $(OUTPUT_DIR)/$(PROJECT_NAME) .
	@echo "Binary written to $(OUTPUT_DIR)/$(PROJECT_NAME)"

.PHONY: run
run: prepare
	go run . $(ARGS)

# ============================================================
# Cross-compilation
# ============================================================

.PHONY: all
all: prepare $(TARGETS)

.PHONY: $(TARGETS)
$(TARGETS):
	@echo "Building for GOOS=$(word 1,$(subst /, ,$@)) GOARCH=$(word 2,$(subst /, ,$@))..."
	@mkdir -p $(OUTPUT_DIR)
	GOOS=$(word 1,$(subst /, ,$@)) GOARCH=$(word 2,$(subst /, ,$@)) \
		$(GO_BUILD) $(OUTPUT_DIR)/$(PROJECT_NAME)-$(word 1,$(subst /, ,$@))-$(word 2,$(subst /, ,$@)) .

# ============================================================
# Install / uninstall
# ============================================================

.PHONY: installed
installed:
	@if [ -f "$(USER_BINARY)" ] || command -v $(PROJECT_NAME) >/dev/null 2>&1; then \
		echo "yes"; \
	else \
		echo "no"; \
	fi

.PHONY: install
install: build
	@mkdir -p $(USER_BIN)
	@cp $(OUTPUT_DIR)/$(PROJECT_NAME) $(USER_BINARY)
	@chmod +x $(USER_BINARY)
	@echo "Installed to $(USER_BINARY)"
	@if ! echo "$$PATH" | tr ':' '\n' | grep -qx "$(USER_BIN)"; then \
		echo ""; \
		echo "WARNING: $(USER_BIN) is not in your PATH."; \
		echo "Add the following line to your shell profile (~/.zshrc, ~/.bashrc, etc.):"; \
		echo ""; \
		echo "    export PATH=\"\$$HOME/bin:\$$PATH\""; \
		echo ""; \
		echo "Then reload your shell: source ~/.zshrc"; \
	fi

.PHONY: uninstall
uninstall:
	@if [ -f "$(USER_BINARY)" ]; then \
		rm -f $(USER_BINARY); \
		echo "Uninstalled $(USER_BINARY)"; \
	else \
		echo "Not installed at $(USER_BINARY) — nothing to remove."; \
	fi

# ============================================================
# Clean
# ============================================================

.PHONY: clean
clean:
	@rm -rf $(OUTPUT_DIR)
	@rm -rf $(OUTPUTS_DIR)
	@echo "Removed $(OUTPUT_DIR)/ and $(OUTPUTS_DIR)/"

.PHONY: clean-all
clean-all: clean uninstall