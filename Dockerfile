FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG GO_BUILD_TAGS="memoize_builders,coraza.rule.no_regex_multiline"

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -tags="${GO_BUILD_TAGS}" -trimpath -ldflags="-s -w" -o /out/coraza-envoy-waf ./cmd/coraza-envoy-waf

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/coraza-envoy-waf /usr/local/bin/coraza-envoy-waf

EXPOSE 9002 9090
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/coraza-envoy-waf"]
