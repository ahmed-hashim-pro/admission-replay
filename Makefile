# Thin wrappers over go, plus the targets that regenerate what the README shows.
GO ?= go
BIN := build/bin
LDFLAGS := -s -w

.PHONY: build test check tools docs example crosscheck demo clean

build:
	CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o admission-replay ./cmd/admission-replay

test:
	$(GO) vet ./...
	$(GO) test ./...

check: build
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	$(GO) vet ./...
	$(GO) test -race ./...

# The programs behind the example and the crosscheck (see hack/).
tools:
	@mkdir -p $(BIN)
	for t in genmonth send retime crosscheck; do CGO_ENABLED=0 $(GO) build -o $(BIN)/$$t ./hack/$$t || exit 1; done

# docs/*.txt are the CLI's real output; the README quotes them verbatim.
docs:
	$(GO) test ./cmd/admission-replay -run TestDocs -update

# Re-record examples/audit.log on a throwaway kind cluster. Needs Docker,
# kind and kubectl.
example: tools
	BIN=$(BIN) hack/record.sh
	$(MAKE) docs

# Replay the example through a real API server for each candidate and
# compare its verdicts with admission-replay's. Needs Docker, kind, kubectl.
crosscheck: tools
	BIN=$(BIN) hack/crosscheck.sh

# Re-record docs/demo.gif with VHS in Docker.
demo: build
	docker run --rm -u $$(id -u):$$(id -g) -e HOME=/tmp -v $(CURDIR):/vhs ghcr.io/charmbracelet/vhs:v0.10.0 docs/demo.tape

clean:
	rm -rf admission-replay build
