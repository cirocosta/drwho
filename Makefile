install:
	go install -v ./cmd/drwho

build:
	go build -v ./cmd/drwho

test:
	go test ./pkg/...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run \
		--config=.golangci.yaml
