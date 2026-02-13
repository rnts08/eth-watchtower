.PHONY: all build test test-race lint performance tests:all clean

all: build

build:
	go build -o eth-watchtower .

test:
	go test -v .

test-race:
	go test -race -v .

lint:
	golangci-lint run

performance:
	go test -bench=. -benchmem

tests:all: test-race lint performance

clean:
	rm -f eth-watchtower
	rm -f *.log
	rm -f *.jsonl