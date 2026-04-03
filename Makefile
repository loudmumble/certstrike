.PHONY: build test lint clean smartpotato cross-compile install

BINARY_NAME=certstrike
SMARTPOTATO_NAME=smartpotato
VERSION?=1.0.0
BUILD_DIR=dist
GO_FILES=$(shell find . -name '*.go' -not -path './vendor/*')

build:
	@echo "Building $(BINARY_NAME)..."
	@CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY_NAME) ./cmd/certstrike

smartpotato:
	@echo "Building $(SMARTPOTATO_NAME) for Windows..."
	@cd implants/smartpotato && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o $(SMARTPOTATO_NAME).exe

test:
	@echo "Running tests..."
	@go test -v -race -cover ./...

lint:
	@echo "Running linters..."
	@go vet ./...
	@go fmt ./...

clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(BINARY_NAME)
	@rm -f implants/smartpotato/$(SMARTPOTATO_NAME)
	@rm -f implants/smartpotato/$(SMARTPOTATO_NAME).exe
	@rm -rf $(BUILD_DIR)

cross-compile:
	@echo "Cross-compiling for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/certstrike
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/certstrike
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/certstrike
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/certstrike
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/certstrike
	@echo "Cross-compilation complete. Binaries in $(BUILD_DIR)/"

install: build
	@echo "Installing $(BINARY_NAME)..."
	@install -m 755 $(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

all: clean build smartpotato test
