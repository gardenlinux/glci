FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.3 AS builder
ARG TARGETARCH

WORKDIR /glci
COPY go.mod go.mod
COPY go.sum go.sum
COPY cmd/ cmd/
COPY internal/ internal/
ARG version=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -a -trimpath -buildvcs=false -o glci \
    -ldflags "-s -w -X main.version=${version}" github.com/gardenlinux/glci/cmd

FROM docker.io/library/debian:forky-20261104-slim
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

USER 65532:65532
