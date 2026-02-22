# Name of the binary
BINARY_NAME=sec

# Build directory
BUILD_DIR=build

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test

# Flags to reduce binary size
# -s: disable symbol table
# -w: disable DWARF generation
LDFLAGS=-ldflags "-s -w"

.PHONY: all clean test build-all linux windows mac

all: build-all

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build for all platforms
build-all: $(BUILD_DIR) linux windows mac freebsd

# Build for Linux (amd64)
linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go
	@echo "Done."
# Build for Windows (amd64)
windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe main.go
	@echo "Done."

# Build for macOS (Universal Binary is harder in pure Go, so we build two versions)
# You can usually just use 'arm64' for modern M1/M2/M3 Macs.
mac: mac-intel mac-silicon

mac-intel:
	@echo "Building for macOS (Intel)..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-mac-amd64 main.go

mac-silicon:
	@echo "Building for macOS (Apple Silicon)..."
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-mac-arm64 main.go
	@echo "Done."

# Build fro FreeBSD
freebsd:
	@echo "Building for FreeBSD..."
	GOOS=freebsd GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-freebsd-amd64 main.go
	@echo "Done."

# Run tests (if you add them later)
test:
	$(GOTEST) -v ./...

# Clean build files
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f *.enc *.dec *.tmp
	@echo "Cleaned."
