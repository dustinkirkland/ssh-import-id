.PHONY: all build clean test install

BINARY_NAME=ssh-import-id
VERSION=6.0
BUILD_DIR=build
GO=go
GOFLAGS=-ldflags="-s -w"

all: build

build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Binary created: $(BUILD_DIR)/$(BINARY_NAME)"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)

build-static:
	@echo "Building static binary..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Static binary created: $(BUILD_DIR)/$(BINARY_NAME)"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)

build-all:
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	@ls -lh $(BUILD_DIR)/

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@$(GO) clean

test:
	$(GO) test -v ./...

install: build
	@echo "Installing to /usr/local/bin..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@sudo chmod 755 /usr/local/bin/$(BINARY_NAME)
	@echo "Installed!"

deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod verify

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

size: build
	@echo "\nBinary size comparison:"
	@echo "Go binary: $$(du -h $(BUILD_DIR)/$(BINARY_NAME) | cut -f1)"
	@echo "Python script: $$(du -h ../ssh_import_id/__init__.py | cut -f1)"
	@echo "Python interpreter: ~15-20 MB"
