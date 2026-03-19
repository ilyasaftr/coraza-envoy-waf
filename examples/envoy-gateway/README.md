# Envoy Gateway Examples

These files show a working integration pattern for `coraza-envoy-waf` with Envoy Gateway.

Files:

- `profiles-configmap.yaml`: example `profiles.yaml` packaged as a ConfigMap
- `coraza-envoy-waf-deployment.yaml`: WAF Deployment
- `coraza-envoy-waf-service.yaml`: WAF Service
- `referencegrant.yaml`: allows `EnvoyExtensionPolicy` in another namespace to reference the WAF Service
- `envoyextensionpolicy-request-only.yaml`: request-phase integration
- `envoyextensionpolicy-request-and-response.yaml`: request and response body integration

Before applying these examples:

- replace route names and namespaces to match your cluster
- make sure the referenced `HTTPRoute` already exists
- pick the profile ConfigMap content that matches the phases you enable

Rule of thumb:

- if the profile has `SecRequestBodyAccess Off`, omit `request.body`
- if the profile has `SecResponseBodyAccess Off`, omit `response.body`
- if response bodies include JSON, add `application/json` to `SecResponseBodyMimeType`

