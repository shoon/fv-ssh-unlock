# SPDX-License-Identifier: Apache-2.0

ARG GO_IMAGE=golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags netgo,osusergo -trimpath \
    -ldflags="-s -w -buildid= -X main.version=${VERSION}" \
    -o /out/fv-ssh-unlock ./cmd/fv-ssh-unlock
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.txt /out/licenses/fv-ssh-unlock/

FROM scratch

ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="fv-ssh-unlock" \
      org.opencontainers.image.description="Monitor and unlock FileVault-protected Macs over SSH" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/shoon/fv-ssh-unlock" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

COPY --from=build /out/ /

USER 65532:65532
ENV HOME=/data \
    FV_SSH_UNLOCK_DATA_DIR=/data
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/fv-ssh-unlock", "healthcheck", "--socket", "/run/fv-ssh-unlock/control.sock"]

ENTRYPOINT ["/fv-ssh-unlock"]
CMD ["daemon", "--socket", "/run/fv-ssh-unlock/control.sock"]
