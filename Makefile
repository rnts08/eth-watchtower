# Makefile for eth-watchtower

BINARY_NAME=eth-watchtower

.PHONY: all build test clean install lint

all: build

build:
	cd src && go build -o ../$(BINARY_NAME)

test:
	cd src && go test -race -v .

lint:
	cd src && golangci-lint run

clean:
	cd src && go clean
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).log

install:
	cd src && go install
