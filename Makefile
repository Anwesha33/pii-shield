.PHONY: setup build test bench holdout run docker clean fmt vet corpus

BINARY := bin/pii-shield

setup:
	go mod download

build:
	go build -ldflags="-s -w" -o $(BINARY) ./cmd/proxy

test:
	go test ./... -count=1

fmt:
	gofmt -w .

vet:
	go vet ./...

# Score the detectors against the corpus used during development. These numbers
# are an upper bound: the detectors were tuned while looking at this data.
bench:
	go run ./cmd/bench -corpus testdata/corpus.jsonl -json bench-results.json

# Score against the held-out corpus, which was never used for tuning. This is
# the number to quote.
holdout:
	go run ./cmd/bench -corpus testdata/holdout.jsonl -json bench-holdout.json

corpus:
	python3 tools/gen_corpus.py
	python3 tools/gen_holdout.py

run: build
	$(BINARY) -config config.yaml

docker:
	docker compose up --build

clean:
	rm -rf bin bench-results.json bench-holdout.json
