# Build the static binary locally before docker build; no credentials or local
# sessions checkout are sent to the image build context. See README.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --chmod=0555 host /host
USER 65532:65532
ENTRYPOINT ["/host"]
