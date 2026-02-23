# Makefile for eth-watchtower

BINARY_NAME=eth-watchtower

.PHONY: all build build-linux build-windows build-darwin build-all test clean install lint performance verify help deploy-azure deploy-gcp deploy-aws

all: build

build:
	go build -o $(BINARY_NAME)

build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-linux-amd64

build-windows:
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME)-windows-amd64.exe

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-darwin-amd64
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_NAME)-darwin-arm64

build-all: build-linux build-windows build-darwin

test:
	go test -race -v .

lint:
	golangci-lint run

performance:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem -run=^$ -v

verify:
	./verify_release.sh

clean:
	go clean
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-linux-amd64 $(BINARY_NAME)-windows-amd64.exe $(BINARY_NAME)-darwin-amd64 $(BINARY_NAME)-darwin-arm64
	rm -f $(BINARY_NAME).log

install:
	go install

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
	@echo "  make deploy-azure - Run test, lint, build and deploy to Azure"
	@echo "  make deploy-gcp   - Run test, lint, build and deploy to GCP"
	@echo "  make deploy-aws   - Run test, lint, build and deploy to AWS"
	@echo "  make help        - Show this help message"

# Deployment targets
DEPLOY_PREFIX ?= eth-watch
DEPLOY_LOCATION ?= 

deploy-azure: test lint build
	./deploy.sh --provider azure --prefix $(DEPLOY_PREFIX) $(if $(DEPLOY_LOCATION),--location $(DEPLOY_LOCATION),)

deploy-gcp: test lint build
	./deploy.sh --provider gcp --prefix $(DEPLOY_PREFIX) $(if $(DEPLOY_LOCATION),--location $(DEPLOY_LOCATION),)

deploy-aws: test lint build
	./deploy.sh --provider aws --prefix $(DEPLOY_PREFIX) $(if $(DEPLOY_LOCATION),--region $(DEPLOY_LOCATION),)
