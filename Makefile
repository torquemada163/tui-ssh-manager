VERSION ?= dev
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: build test check smoke release

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/sshm ./cmd/sshm

test:
	go test -race ./...

check:
	go vet ./...

smoke: build
	python3 scripts/terminal_smoke.py ./bin/sshm

release:
	@mkdir -p bin
	@for platform in darwin linux; do \
		for arch in arm64 amd64; do \
			CGO_ENABLED=0 GOOS=$$platform GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o bin/sshm-$$platform-$$arch ./cmd/sshm || exit 1; \
		done; \
	done
