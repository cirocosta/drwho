install:
	go install -v ./cmd/drwho

build:
	go build -v ./cmd/drwho

test:
	go test ./pkg/...

lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint run \
		--config=.golangci.yaml
