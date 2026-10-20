# Input context contains only the two reproducibly built static binaries.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS runtime
LABEL org.opencontainers.image.source="https://github.com/Azure/aks-durable-agents" \
      org.opencontainers.image.licenses="MIT"
USER 65532:65532

FROM runtime AS host
# Production host, with the reference profile's required readiness helper.
COPY --chmod=0555 host /host
COPY --chmod=0555 session-fixture /session-fixture
ENTRYPOINT ["/host"]

FROM runtime AS session-fixture
LABEL org.opencontainers.image.description="Reference release-notes fixture: harness, durable local executor and inert fake; not a production agent"
COPY --chmod=0555 session-fixture /session-fixture
ENTRYPOINT ["/session-fixture"]
