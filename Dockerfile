FROM golang:1.26-bookworm AS builder

WORKDIR /build

COPY go.mod ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH
ARG SPIVOT_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_BRANCH=unknown
ARG BUILD_TIME=unknown

RUN test -n "${TARGETARCH}" || (echo "TARGETARCH build argument must be set" >&2; exit 1) && \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath \
      -ldflags="-s -w \
        -X github.com/wheelsdown/spivot-server/internal/platform/buildinfo.Version=${SPIVOT_VERSION} \
        -X github.com/wheelsdown/spivot-server/internal/platform/buildinfo.GitCommit=${BUILD_COMMIT} \
        -X github.com/wheelsdown/spivot-server/internal/platform/buildinfo.GitBranch=${BUILD_BRANCH} \
        -X github.com/wheelsdown/spivot-server/internal/platform/buildinfo.BuildTime=${BUILD_TIME}" \
      -o /out/spivot-server ./cmd/spivot-server

FROM scratch AS artifact

COPY --from=builder /out/spivot-server /spivot-server

FROM scratch

ARG SPIVOT_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_BRANCH=unknown
ARG BUILD_TIME=unknown

LABEL \
    org.opencontainers.image.title="Spivot Server" \
    org.opencontainers.image.description="Backend API service for Spivot" \
    org.opencontainers.image.authors="wheelsdown" \
    org.opencontainers.image.url="https://github.com/wheelsdown/spivot-server" \
    org.opencontainers.image.source="https://github.com/wheelsdown/spivot-server" \
    org.opencontainers.image.vendor="wheelsdown" \
    org.opencontainers.image.version="${SPIVOT_VERSION}" \
    org.opencontainers.image.ref.name="${SPIVOT_VERSION}" \
    org.opencontainers.image.revision="${BUILD_COMMIT}" \
    org.opencontainers.image.created="${BUILD_TIME}" \
    org.opencontainers.image.base.name="scratch"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/spivot-server /usr/local/bin/spivot-server

USER 65532:65532
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD ["/usr/local/bin/spivot-server", "healthcheck", "-url", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["/usr/local/bin/spivot-server"]
CMD ["serve"]
