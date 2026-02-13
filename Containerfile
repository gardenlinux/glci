FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.25.7 AS builder
ARG TARGETOS
ARG TARGETARCH

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get --no-install-suggests --no-install-recommends -o Dpkg::Options::="--force-confnew" --allow-downgrades --allow-remove-essential \
    --allow-change-held-packages -fuy install \
    \
    ca-certificates \
    curl \
    lsb-release \
    \
    && \
    curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg && \
    printf "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list && \
    apt-get update && \
    apt-get install vault && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /glci
COPY go.mod go.mod
COPY go.sum go.sum
COPY cmd/ cmd/
COPY internal/ internal/
ARG version=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o glci \
    -ldflags "-X main.version=${version}" github.com/gardenlinux/glci/cmd

FROM docker.io/library/debian:forky-20260202-slim
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
COPY --from=builder /usr/bin/vault /usr/bin/vault

ENV GLCI_PUBLISHING_CREDENTIALS_TOKEN_FILE= GLCI_PUBLISHING_CREDENTIALS_ROLE_ID= GLCI_PUBLISHING_CREDENTIALS_SECRET_ID=
ENTRYPOINT ["/glci"]
COPY --from=builder /glci/glci .
COPY glci.yaml glci.yaml
COPY glci_1877.yaml glci_1877.yaml
COPY glci_1592.yaml glci_1592.yaml
COPY glci_integration_test.yaml glci_integration_test.yaml
COPY glci_dev.yaml glci_dev.yaml

USER 65532:65532
