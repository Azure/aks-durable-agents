.PHONY: image-binaries images demo

IMAGE_CONTEXT ?= .build/images
IMAGE_PREFIX ?= local/aks-durable-agents

# Build only the production host and reference fixture, never either drillhost.
image-binaries:
	mkdir -p "$(IMAGE_CONTEXT)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= -o "$(IMAGE_CONTEXT)/host" ./cmd/host
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= -o "$(IMAGE_CONTEXT)/session-fixture" ./cmd/session-fixture

images: image-binaries
	docker build --network=none --platform linux/amd64 -f images/Dockerfile --target host -t "$(IMAGE_PREFIX)/host:local" "$(IMAGE_CONTEXT)"
	docker build --network=none --platform linux/amd64 -f images/Dockerfile --target session-fixture -t "$(IMAGE_PREFIX)/session-fixture:local" "$(IMAGE_CONTEXT)"

# Separate local fake-model image; never changes or publishes production images.
demo:
	python3 -B ops/demo/demo.py
