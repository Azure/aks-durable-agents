# HOST_IMAGE is required and supplied from the chart's verified digest pins.
ARG HOST_IMAGE
FROM ${HOST_IMAGE} AS production

FROM golang:1.27.2@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8 AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
COPY modeltransport ./modeltransport
COPY entraauth ./entraauth
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= -o /out/host ./cmd/demo-host && \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= -o /out/demo-client ./cmd/demo-client

FROM production
LABEL org.opencontainers.image.title="Local fake-model demo host" \
      org.opencontainers.image.description="DEMO ONLY: deterministic local model, unauthenticated loopback API; never use as a production host"
COPY --from=production --chmod=0555 /host /production-host
COPY --from=build --chmod=0555 /out/host /host
COPY --from=build --chmod=0555 /out/demo-client /demo-client
USER 65532:65532
ENTRYPOINT ["/host"]
