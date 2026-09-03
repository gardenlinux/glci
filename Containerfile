FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.1 AS builder
ARG TARGETARCH

WORKDIR /glci
COPY go.mod go.mod
COPY go.sum go.sum
COPY cmd/ cmd/
COPY internal/ internal/
ARG version=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -a -trimpath -buildvcs=false -o glci \
    -ldflags "-s -w -X main.version=${version}" github.com/gardenlinux/glci/cmd

FROM docker.io/library/debian:forky-20260824-slim
WORKDIR /
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get --no-install-suggests --no-install-recommends -o Dpkg::Options::="--force-confnew" --allow-downgrades --allow-remove-essential \
    --allow-change-held-packages -fuy install \
    \
    ca-certificates \
    curl \
    jq \
    \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/glci"]
COPY --from=builder /glci/glci .
COPY glci.yaml glci.yaml
COPY glci_2150.yaml glci_2150.yaml
COPY glci_1877.yaml glci_1877.yaml
COPY glci_dev.yaml glci_dev.yaml

USER 65532:65532
