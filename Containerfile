FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.24.5 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /glci
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o glci github.com/gardenlinux/glci/cmd

FROM docker.io/library/debian:bookworm-20250630-slim
WORKDIR /
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get --no-install-suggests --no-install-recommends -o Dpkg::Options::="--force-confnew" --allow-downgrades --allow-remove-essential \
    --allow-change-held-packages -fuy install \
    \
    ca-certificates \
    \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENV GLCI_CREDENTIALS_FILE=/gardenlinux-credentials.json GLCI_CREDENTIALS_BASE64='' GLCI_DEV=''
ENTRYPOINT ["/glci"]
COPY --from=builder /glci/glci .
COPY glci.yaml glci.yaml
COPY glci_integration_test.yaml glci_integration_test.yaml

USER 65532:65532
