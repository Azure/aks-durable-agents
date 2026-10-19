# HOST_IMAGE must be the approved digest-pinned chart host image containing
# /host and the matching release-notes-v2 /session-fixture replay/probe binary.
ARG HOST_IMAGE
FROM ${HOST_IMAGE} AS host
FROM python:3.13-alpine@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f
COPY --from=host /host /host
COPY --from=host /session-fixture /session-fixture
COPY --chmod=0444 backup.py /backup.py
USER 65532:65532
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python3", "/backup.py"]
