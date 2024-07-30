PROJECT_NAME := entpassgen
SHELL := bash
OUTPUT_DIR := bin
OUTPUTS_DIR := outputs
COVER_OUT := $(OUTPUTS_DIR)/coverage.out
COVER_JSON := $(OUTPUTS_DIR)/coverage.json
GO_BUILD := go build -o
TARGETS := \
	darwin/amd64 \
	darwin/arm64 \
	linux/amd64 \
	linux/arm64 \
	windows/amd64

.PHONY: help
help:
	@echo "Makefile for $(PROJECT_NAME)"
	@echo
	@echo "Usage:"
	@echo "  make [target]"
	@echo
	@echo "Targets:"
	@echo "  all       Build binaries for all target OS/Arch combinations"
	@echo "  run       Run the Go code directly"
	@echo "  coverage  Generate coverage report"
	@echo "  test      Run all tests"
	@echo "  prepare   Run gofmt on *.go files"
	@echo "  clean     Remove all binaries"
	@echo "  help      Display this help message"
	@echo
	@echo "Target OS/Arch combinations:"
	@echo "  darwin/amd64"
	@echo "  darwin/arm64"
	@echo "  linux/amd64"
	@echo "  linux/arm64"
	@echo "  windows/amd64"

.PHONY: all
all: prepare $(TARGETS)

.PHONY: install
install:
	@go build -o entpassgen .
	@chmod +x entpassgen
	@[ -f /usr/bin/entpassgen ] && sudo rm -rf /usr/bin/entpassgen || echo "Can't remove /usr/bin/entpassgen...NOT FOUND"
	@sudo mv entpassgen /usr/bin/entpassgen
	@which entpassgen
	@entpassgen -h

.PHONY: uninstall
uninstall:
	@[ -f /usr/bin/entpassgen ] && \
		read -t 33 -r -p "Deleting /usr/bin/entpassgen in 33s unless you respond with 'stop'. Enter to do it. Response: " response && \
		{ [[ "$${response,,}" == "stop" ]] && echo "Skipped removing /usr/bin/entpassgen...USER INTERVENTION"; } || \
		{ sudo rm -rf /usr/bin/entpassgen && echo "Uninstalled /usr/bin/entpassgen"; } || echo "Skipped removing /usr/bin/entpassgen...NOT FOUND";


.PHONY: prepare
prepare:
	@go mod tidy 1> /dev/null || echo SKIPPED TIDY
	@go mod download 1> /dev/null || echo SKIPPED DOWNLOAD
	@/usr/bin/find . -type f -name '*.go' -exec gofmt -w {} \; || echo SKIPPED FMT 

.PHONY: $(TARGETS)
$(TARGETS): 
	@echo "Building for GOOS=$(word 1,$(subst /, ,$@)) GOARCH=$(word 2,$(subst /, ,$@))..."
	GOOS=$(word 1,$(subst /, ,$@)) GOARCH=$(word 2,$(subst /, ,$@)) $(GO_BUILD) $(OUTPUT_DIR)/$(PROJECT_NAME)-$(word 1,$(subst /, ,$@))-$(word 2,$(subst /, ,$@)) .

.PHONY: clean
clean:
	@rm -rf $(OUTPUT_DIR)
	@rm -rf $(OUTPUTS_DIR)
	@[ -f ./entpassgen ] && rm -rf ./entpassgen || echo "Skipped removing ./entpassgen... NOT FOUND"
	@[ -f /usr/bin/entpassgen ] && \
		read -t 33 -r -p "Deleting /usr/bin/entpassgen in 33s unless you respond with 'stop'. Enter to do it. Response: " response && \
		{ [[ "$${response,,}" == "stop" ]] && echo "Skipped removing /usr/bin/entpassgen...USER INTERVENTION"; } || \
		{ sudo rm -rf /usr/bin/entpassgen && echo "Uninstalled /usr/bin/entpassgen"; } || echo "Skipped removing /usr/bin/entpassgen...NOT FOUND";
	
.PHONY: run
run: prepare
	go run . $(ARGS)

.PHONY: build
build: prepare
	go build .

.PHONY: test
test: prepare
	@mkdir -p $(OUTPUTS_DIR)
	@go test -json  ./... $(ARGS) > $(OUTPUTS_DIR)/tests.json 2> /dev/null
	go test ./... 

.PHONY: coverage
coverage:
	@mkdir -p $(OUTPUTS_DIR)
	@go test -coverprofile=$(COVER_OUT)
	@go tool cover -func=$(COVER_OUT)
	@go tool cover -o $(COVER_JSON) -func=$(COVER_OUT)

