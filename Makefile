VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
TARGETS := linux/amd64 linux/arm64 darwin/arm64 windows/amd64

TRAY_TARGETS := linux/amd64 linux/arm64 windows/amd64

.PHONY: build tray test vet cross integration clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/backhaul ./cmd/backhaul

# Tray app for this machine. On macOS it needs cgo (Cocoa): run this on a Mac.
tray:
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/backhaul-tray ./cmd/backhaul-tray

test:
	go test ./...

vet:
	@for t in $(TARGETS); do echo "vet $$t"; GOOS=$${t%/*} GOARCH=$${t#*/} go vet ./... || exit 1; done

# Static binaries for every supported platform in dist/.
cross:
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "build $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o dist/backhaul_$${os}_$${arch}$$ext ./cmd/backhaul || exit 1; \
	done
	@for t in $(TRAY_TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; ext=; gui=; [ $$os = windows ] && ext=.exe && gui=-H=windowsgui; \
		echo "build tray $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS) '"$$gui" \
			-o dist/backhaul-tray_$${os}_$${arch}$$ext ./cmd/backhaul-tray || exit 1; \
	done

# Linux network-namespace end-to-end test (root required).
integration:
	sudo -E bash test/integration/netns.sh

clean:
	rm -rf bin dist
