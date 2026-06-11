.PHONY: build run test clean

build:
	go build -o bin/aegis ./cmd/aegis/

run: build
	./bin/aegis --port 8080 --output report.json

test:
	go test ./... -v

clean:
	rm -rf bin/
	rm -f report.json
