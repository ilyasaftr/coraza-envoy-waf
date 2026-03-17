FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build

ARG TARGETOS
ARG TARGETARCH
ARG GO_BUILD_TAGS="memoize_builders,coraza.rule.no_regex_multiline,re2_cgo,libinjection_cgo"
ARG LIBINJECTION_VERSION=4aa3894b21d03d9d8fc364505c0617d2aca73fc1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libre2-dev \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /tmp/libinjection \
  && curl -fsSL "https://github.com/libinjection/libinjection/archive/${LIBINJECTION_VERSION}.tar.gz" \
    | tar -xz --strip-components=1 -C /tmp/libinjection \
  && cd /tmp/libinjection \
  && autoreconf -fi \
  && ./configure \
  && make -j"$(nproc)" install \
  && ldconfig \
  && rm -rf /tmp/libinjection

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -tags="${GO_BUILD_TAGS}" -trimpath -ldflags="-s -w" -o /out/coraza-envoy-waf ./cmd/coraza-envoy-waf

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libre2-9 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/lib/libinjection.so* /usr/local/lib/
COPY --from=build /out/coraza-envoy-waf /usr/local/bin/coraza-envoy-waf
RUN ldconfig

EXPOSE 9002 9090
USER 65532:65534
ENTRYPOINT ["/usr/local/bin/coraza-envoy-waf"]

FROM runtime AS smoke

USER root
RUN apt-get update && apt-get install -y --no-install-recommends curl \
  && rm -rf /var/lib/apt/lists/*

RUN printf '%s\n' \
    'default_profile: default' \
    'profiles:' \
    '  default:' \
    '    mode: detect' \
  > /tmp/profiles.yaml

RUN set -eux; \
    WAF_PROFILES_PATH=/tmp/profiles.yaml \
    GRPC_BIND=127.0.0.1:19002 \
    METRICS_BIND=127.0.0.1:19090 \
    LOG_LEVEL=error \
    /usr/local/bin/coraza-envoy-waf >/tmp/coraza-envoy-waf.log 2>&1 & \
    pid="$!"; \
    trap 'kill "$pid" >/dev/null 2>&1 || true' EXIT; \
    for _ in $(seq 1 30); do \
      if curl -fsS http://127.0.0.1:19090/healthz >/dev/null; then \
        break; \
      fi; \
      sleep 1; \
    done; \
    curl -fsS http://127.0.0.1:19090/healthz >/dev/null; \
    kill "$pid"; \
    wait "$pid" || true

FROM runtime AS final
