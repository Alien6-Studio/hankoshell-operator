ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine3.23@sha256:e57c41c1d5864341031181b0db34b9a537bb5773eb6428e4e5bdaea0f9135406 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api ./api
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath \
    -ldflags "-X github.com/Alien6-Studio/hankoshell-operator/internal/version.Agent=${VERSION}" \
    -o /hankoshell-operator ./cmd/operator

FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine3.23@sha256:e57c41c1d5864341031181b0db34b9a537bb5773eb6428e4e5bdaea0f9135406 AS cosign
ARG TARGETOS
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /cosign-source
# Public module downloads retain checksum-database verification. Recompile the
# reviewed release with the supported Go runtime and patched verification SDKs.
RUN go mod download github.com/sigstore/cosign/v3@v3.1.3 \
    && cp -R /go/pkg/mod/github.com/sigstore/cosign/v3@v3.1.3/. . \
    && chmod -R u+w . \
    && go get golang.org/x/crypto@v0.55.0 golang.org/x/mod@v0.40.0 \
        golang.org/x/text@v0.41.0 google.golang.org/grpc@v1.83.2 \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath \
        -ldflags '-s -w' -o /cosign ./cmd/cosign

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=builder /hankoshell-operator /hankoshell-operator
COPY --from=cosign /cosign /usr/local/bin/cosign
COPY LICENSE NOTICE /usr/share/licenses/hankoshell-operator/
USER 65534
ENTRYPOINT ["/hankoshell-operator"]
