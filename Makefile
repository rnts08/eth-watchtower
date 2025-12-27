# Makefile for eth-watchtower

BINARY_NAME=eth-watchtower

.PHONY: all build test clean install

all: build

build:
	go build -o $(BINARY_NAME)

test:
	go test -race -v .

clean:
	go clean
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).log
	rm -f *.jsonl

install:
	go install