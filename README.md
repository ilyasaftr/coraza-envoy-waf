# Coraza Envoy WAF

A gRPC `ext_proc` service that inspects HTTP requests and responses using [Coraza](https://github.com/corazawaf/coraza) + OWASP CRS, designed for use with Envoy Gateway.

## Features

- Full request and response inspection (headers + body)
- Coraza-native engine modes via `SecRuleEngine On|DetectionOnly|Off`
- Service-internal action errors are hardcoded fail-open and still logged
- Prometheus metrics and health endpoint
- No Proxy-WASM required

## Performance Build

- Default Docker/CI builds now use CGO with `memoize_builders,coraza.rule.no_regex_multiline,re2_cgo,libinjection_cgo`.
- The service contract stays the same for `ext_proc` decisions, deny headers/details, and profile resolution.
- Before promoting a perf image, run the contract checks and confirm the deny envelope still matches current behavior:
  - Ensure native deps are installed (`re2` + `libinjection`) or run inside the project CI workflow.
  - `go test -tags "memoize_builders,coraza.rule.no_regex_multiline,re2_cgo,libinjection_cgo" ./...`
  - `go test ./internal/extproc/... ./internal/waf/...`
- Roll back by pinning the previous image digest instead of reusing a mutable tag:
  - `CORAZA_EXT_PROC_IMAGE=ghcr.io/<org>/coraza-envoy-waf@sha256:<previous_digest> make apply-global`

## Configuration

| Variable | Default | Description |
|---|---|---|
| `WAF_PROFILES_PATH` | — | Path to `profiles.yaml` (required) |
| `GRPC_BIND` | `:9002` | gRPC bind address |
| `METRICS_BIND` | `:9090` | HTTP bind for `/healthz` and `/metrics` |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `GRPC_NUM_STREAM_WORKERS` | `0` | grpc-go stream worker count; `0` disables the experimental worker pool |

## profiles.yaml

```yaml
default_profile: default
profiles:
  default:
    directives: |
      Include @coraza.conf-recommended
      SecRuleEngine DetectionOnly
      SecRequestBodyAccess On
      SecRequestBodyLimit 1048576
      SecRequestBodyLimitAction Reject
      SecResponseBodyAccess On
      SecResponseBodyLimit 1048576
      SecResponseBodyLimitAction Reject
      Include @crs-setup.conf.example
      SecAction "id:10000001,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=1"
      SecAction "id:10000002,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=10"
      SecAction "id:10000003,phase:1,pass,nolog,t:none,setvar:tx.outbound_anomaly_score_threshold=8"
      Include @owasp_crs/*.conf
      SecRuleRemoveById 941130
  strict:
    directives: |
      Include @coraza.conf-recommended
      SecRuleEngine On
      SecRequestBodyAccess On
      SecRequestBodyLimit 1048576
      SecRequestBodyLimitAction Reject
      SecResponseBodyAccess On
      SecResponseBodyLimit 1048576
      SecResponseBodyLimitAction Reject
      SecResponseBodyMimeType text/plain text/html text/xml application/json
      Include @crs-setup.conf.example
      SecAction "id:10000101,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=1"
      SecAction "id:10000102,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=5"
      SecAction "id:10000103,phase:1,pass,nolog,t:none,setvar:tx.outbound_anomaly_score_threshold=4"
      SecAction "id:10000104,phase:1,pass,nolog,t:none,setvar:tx.early_blocking=1"
      Include @owasp_crs/*.conf
```

Profile contract:

| Field | Values | Description |
|---|---|---|
| `directives` | multiline Coraza directives | Required. Effective engine behavior is whatever Coraza resolves from these directives and any included files. |

Notes:

- `profiles.yaml` is now the only WAF configuration source. Thresholds, exclusions, paranoia, body limits, MIME handling, early blocking, and custom rules all live inside `directives`.
- If you include `@coraza.conf-recommended`, remember it sets `SecRuleEngine DetectionOnly` unless a later directive overrides it.
- Service-internal action errors are hardcoded fail-open. They remain visible in structured logs but no longer have a configurable `on_error` policy.
- Threshold logging derives values from raw directives (`threshold_source=profile_directive`) and falls back to embedded CRS defaults (`threshold_source=crs_default`) when no override is present.

## Envoy Gateway `processingMode` Alignment

`coraza-envoy-waf` only inspects the phases Envoy sends through `ext_proc`, so `EnvoyExtensionPolicy.spec.extProc[].processingMode` must match the Coraza directives in your active profile.

Important:

- Envoy Gateway `v1.7.x` does not support `body: None`. To disable body forwarding, omit the `body` field entirely.
- If you rely on route-based profile selection, keep `request.attributes` with `xds.route_name` and `xds.route_metadata`.

| Coraza profile intent | Envoy `processingMode` | Required Coraza directives | Notes |
|---|---|---|---|
| Request headers only | `request` block present, no `request.body` | none beyond normal rules | Request headers are sent when the `request` block exists. Keep `request.attributes` if you use route metadata. |
| Request body inspection | `request.body: Buffered` | `SecRequestBodyAccess On` | Use `Buffered` for deterministic CRS body inspection and body-limit enforcement. |
| Response headers only | `response` block present, no `response.body` | none beyond normal rules | Add a `response` block only when you actually want response-phase processing. |
| Response body inspection | `response.body: Buffered` | `SecResponseBodyAccess On` | If responses are JSON, also set `SecResponseBodyMimeType ... application/json` or Coraza will ignore the body. |
| No body inspection | omit `request.body` and omit `response.body` | `SecRequestBodyAccess Off`, `SecResponseBodyAccess Off` | This avoids extra gRPC/body buffering overhead for bodies Coraza will not inspect. |

Examples:

Request headers plus route metadata only:

```yaml
processingMode:
  request:
    attributes:
      - xds.route_name
      - xds.route_metadata
```

Request body inspection enabled:

```yaml
processingMode:
  request:
    attributes:
      - xds.route_name
      - xds.route_metadata
    body: Buffered
```

Request and response body inspection enabled:

```yaml
processingMode:
  request:
    attributes:
      - xds.route_name
      - xds.route_metadata
    body: Buffered
  response:
    body: Buffered
```

Current `k3s-learn` strict profile keeps both `SecRequestBodyAccess Off` and `SecResponseBodyAccess Off`, so the matching `EnvoyExtensionPolicy` should omit both body fields.
