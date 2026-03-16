# Coraza Envoy WAF

A gRPC `ext_proc` service that inspects HTTP requests and responses using [Coraza](https://github.com/corazawaf/coraza) + OWASP CRS, designed for use with Envoy Gateway.

## Features

- Full request and response inspection (headers + body)
- Two WAF modes: `detect` (log only) and `block` (deny with HTTP 403)
- Configurable error handling per processing phase (`allow` or `deny`)
- Prometheus metrics and health endpoint
- No Proxy-WASM required

## Configuration

| Variable | Default | Description |
|---|---|---|
| `WAF_PROFILES_PATH` | — | Path to `profiles.yaml` (required) |
| `GRPC_BIND` | `:9002` | gRPC bind address |
| `METRICS_BIND` | `:9090` | HTTP bind for `/healthz` and `/metrics` |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

## profiles.yaml

```yaml
default_profile: default
profiles:
  default:
    mode: detect
  strict:
    mode: block
    excluded_rule_ids: [941130]
    inbound_anomaly_score_threshold: 5
    outbound_anomaly_score_threshold: 5
    request_body_limit_bytes: 1048576
    response_body_limit_bytes: 1048576
    response_body_mime_types: [text/plain, text/html, text/xml, application/json]
    on_error:
      default: deny
      request_body: allow
```

Full options:

| Field | Values | Description |
|---|---|---|
| `mode` | `detect` \| `block` | Detect logs interruptions; block denies with 403 |
| `on_error.default` | `allow` \| `deny` | Response when a processing error occurs |
| `excluded_rule_ids` | list of ints | Rule IDs to skip |
| `inbound_anomaly_score_threshold` | int | Anomaly score limit for requests |
| `outbound_anomaly_score_threshold` | int | Anomaly score limit for responses |
| `request_body_limit_bytes` | int | Max request body size to inspect |
| `response_body_limit_bytes` | int | Max response body size to inspect |
| `response_body_mime_types` | list of MIME types | Optional override for `SecResponseBodyMimeType` per profile |

When `response_body_mime_types` is not set for a profile, the service keeps Coraza recommended defaults from `@coraza.conf-recommended`.
Response body limit handling is enforced with `SecResponseBodyLimitAction Reject`.
