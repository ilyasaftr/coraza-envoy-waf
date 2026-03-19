# Coraza Envoy WAF

`coraza-envoy-waf` is a gRPC `ext_proc` service for [Envoy Gateway](https://gateway.envoyproxy.io/) that runs [Coraza](https://github.com/corazawaf/coraza) with the OWASP Core Rule Set.

It is designed for operators who want to attach WAF inspection to Gateway API routes without using Proxy-WASM.

## What It Does

- Inspects HTTP traffic with Coraza + OWASP CRS
- Works with Envoy Gateway through `EnvoyExtensionPolicy`
- Uses `profiles.yaml` to define WAF behavior
- Exposes `/healthz` and `/metrics`
- Supports request and response inspection when Envoy forwards those phases

## When To Use It

Use this service when you want:

- route-level WAF policy in Envoy Gateway
- Coraza profiles managed as plain YAML
- Prometheus-friendly health and metrics
- a separate WAF service instead of an in-proxy filter

## Quick Start

The service needs a `profiles.yaml` file and listens on:

- gRPC: `:9002`
- metrics and health: `:9090`

Minimal startup example:

```bash
docker run --rm \
  -p 9002:9002 \
  -p 9090:9090 \
  -v "$PWD/examples/profiles/strict-minimal.yaml:/etc/coraza/profiles.yaml:ro" \
  -e WAF_PROFILES_PATH=/etc/coraza/profiles.yaml \
  ghcr.io/ilyasaftr/coraza-envoy-waf:latest
```

Example files:

- Profiles: [`examples/profiles/`](examples/profiles/)
- Envoy Gateway manifests: [`examples/envoy-gateway/`](examples/envoy-gateway/)

## Configuration

| Variable | Default | Description |
|---|---|---|
| `WAF_PROFILES_PATH` | — | Path to `profiles.yaml`. Required. |
| `GRPC_BIND` | `:9002` | Address for the ext-proc gRPC server. |
| `METRICS_BIND` | `:9090` | Address for `/healthz` and `/metrics`. |
| `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error`. |
| `GRPC_NUM_STREAM_WORKERS` | `0` | Optional grpc-go stream worker count. `0` keeps it disabled. |
| `GRPC_MAX_CONCURRENT_STREAMS` | `4096` | Maximum concurrent gRPC streams accepted by the server. |
| `REQUEST_BODY_FAST_PATH_MODE` | `strict` | Request fast-path mode for safe bodyless traffic. `strict` or `off`. |

## Profiles

`profiles.yaml` is the source of WAF behavior. Each profile contains raw Coraza directives.

At minimum, a profile usually defines:

- `SecRuleEngine`
- request and response body access
- CRS setup includes
- optional thresholds, exclusions, MIME types, and custom rules

Sample files:

- [`examples/profiles/detect-minimal.yaml`](examples/profiles/detect-minimal.yaml)
- [`examples/profiles/strict-minimal.yaml`](examples/profiles/strict-minimal.yaml)
- [`examples/profiles/request-and-response-inspection.yaml`](examples/profiles/request-and-response-inspection.yaml)

Operational notes:

- `profiles.yaml` is loaded at startup
- route-based profile selection depends on request attributes such as `xds.route_name` and `xds.route_metadata`
- service-internal processing errors are fail-open and remain visible in logs

## Envoy Gateway Integration

Envoy Gateway must forward the phases that Coraza should inspect. If Envoy does not send a phase, `coraza-envoy-waf` cannot inspect it.

Important:

- Envoy Gateway `v1.7.x` does not support `body: None`
- To disable body forwarding, omit the `body` field entirely
- If you use route-based profile selection, include:
  - `xds.route_name`
  - `xds.route_metadata`

Decision table:

| If your Coraza profile does this | Use this in `processingMode` |
|---|---|
| Request headers only | Keep a `request` block and omit `request.body` |
| Request body inspection | Set `request.body: Buffered` |
| Response headers only | Keep a `response` block and omit `response.body` |
| Response body inspection | Set `response.body: Buffered` |
| No request body inspection | Omit `request.body` |
| No response body inspection | Omit `response.body` |

If you want JSON response inspection, your profile must also include `application/json` in `SecResponseBodyMimeType`.

Full examples:

- [`examples/envoy-gateway/envoyextensionpolicy-request-only.yaml`](examples/envoy-gateway/envoyextensionpolicy-request-only.yaml)
- [`examples/envoy-gateway/envoyextensionpolicy-request-and-response.yaml`](examples/envoy-gateway/envoyextensionpolicy-request-and-response.yaml)
- [`examples/envoy-gateway/README.md`](examples/envoy-gateway/README.md)

## Observability

The service exposes:

- `/healthz` for readiness and liveness checks
- `/metrics` for Prometheus scraping

The metrics endpoint is intended for service health and traffic visibility. Logs are structured and useful for deny events, profile selection, and troubleshooting.

## Build Note

The published image uses the repository Dockerfile and the default performance-oriented build path. For custom image builds, use the included [`Dockerfile`](Dockerfile) or the GitHub Actions workflows in [`.github/workflows/`](.github/workflows/).
