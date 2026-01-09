# Makefile for eth-watchtower

BINARY_NAME=eth-watchtower

.PHONY: all build test clean install lint performance help

all: build

build:
	cd src && go build -o ../$(BINARY_NAME)

test:
	cd src && go test -race -v .

lint:
	cd src && golangci-lint run

performance:
	@echo "Running benchmarks..."
	cd src && go test -bench=. -benchmem -run=^$ -v

clean:
	cd src && go clean
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).log

install:
	cd src && go install

help:
	@echo "Available commands:"
	@echo "  make build       - Build the application"
	@echo "  make test        - Run unit tests"
	@echo "  make lint        - Run static analysis"
	@echo "  make performance - Run benchmarks"
	@echo "  make install     - Install binary to GOPATH/bin"
	@echo "  make clean       - Remove binary and logs"
	@echo "  make help        - Show this help message"
