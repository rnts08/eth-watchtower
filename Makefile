# Makefile for eth-watchtower

BINARY_NAME=eth-watchtower

.PHONY: all build build-linux build-windows build-darwin build-all test clean install lint performance verify help

all: build

build:
	cd src && go build -o ../$(BINARY_NAME)

build-linux:
	cd src && GOOS=linux GOARCH=amd64 go build -o ../$(BINARY_NAME)-linux-amd64

build-windows:
	cd src && GOOS=windows GOARCH=amd64 go build -o ../$(BINARY_NAME)-windows-amd64.exe

build-darwin:
	cd src && GOOS=darwin GOARCH=amd64 go build -o ../$(BINARY_NAME)-darwin-amd64
	cd src && GOOS=darwin GOARCH=arm64 go build -o ../$(BINARY_NAME)-darwin-arm64

build-all: build-linux build-windows build-darwin

test:
	cd src && go test -race -v .

lint:
	cd src && golangci-lint run

performance:
	@echo "Running benchmarks..."
	cd src && go test -bench=. -benchmem -run=^$ -v

verify:
	./verify_release.sh

clean:
	cd src && go clean
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-linux-amd64 $(BINARY_NAME)-windows-amd64.exe $(BINARY_NAME)-darwin-amd64 $(BINARY_NAME)-darwin-arm64
	rm -f $(BINARY_NAME).log

install:
	cd src && go install

help:
	@echo "Available commands:"
	@echo "  make build       - Build the application"
	@echo "  make build-all   - Build for all platforms (Linux, Windows, macOS)"
	@echo "  make test        - Run unit tests"
	@echo "  make lint        - Run static analysis"
	@echo "  make performance - Run benchmarks"
	@echo "  make verify      - Verify release artifacts (requires checksums.txt)"
	@echo "  make install     - Install binary to GOPATH/bin"
	@echo "  make clean       - Remove binary and logs"
	@echo "  make help        - Show this help message"
