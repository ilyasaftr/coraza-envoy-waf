package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func TestLoadDefaultsFromProfilesYAML(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: default
profiles:
  default:
    mode: block
`)

	t.Setenv(EnvGRPCBind, "")
	t.Setenv(EnvMetricsBind, "")
	t.Setenv(EnvLogLevel, "")
	t.Setenv(EnvWAFProfilesPath, profilesPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.GRPCBind != ":9002" {
		t.Fatalf("unexpected grpc bind: %q", cfg.GRPCBind)
	}
	if cfg.MetricsBind != ":9090" {
		t.Fatalf("unexpected metrics bind: %q", cfg.MetricsBind)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Fatalf("unexpected log level: %v", cfg.LogLevel)
	}
	if cfg.DefaultProfile != "default" {
		t.Fatalf("unexpected default profile: %q", cfg.DefaultProfile)
	}

	profile := cfg.Profiles["default"]
	if profile.Mode != model.ModeBlock {
		t.Fatalf("unexpected mode: %q", profile.Mode)
	}
	if profile.RequestBodyLimit != 1048576 {
		t.Fatalf("unexpected request body limit: %d", profile.RequestBodyLimit)
	}
	if profile.ResponseBodyLimit != 1048576 {
		t.Fatalf("unexpected response body limit: %d", profile.ResponseBodyLimit)
	}
	if profile.OnError.Default != model.ErrorPolicyDeny {
		t.Fatalf("unexpected on_error default: %q", profile.OnError.Default)
	}
	if len(profile.OnError.Overrides) != 0 {
		t.Fatalf("unexpected on_error overrides: %+v", profile.OnError.Overrides)
	}
}

func TestLoadCustomProfileValues(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    mode: block
    excluded_rule_ids: [942100, 941130, 942100]
    inbound_anomaly_score_threshold: 9
    outbound_anomaly_score_threshold: 7
    request_body_limit_bytes: 4096
    response_body_limit_bytes: 8192
    response_body_mime_types: [application/json, text/plain, application/json]
    on_error:
      default: allow
      request_body: deny
      response_body: allow
`)

	t.Setenv(EnvGRPCBind, "127.0.0.1:10000")
	t.Setenv(EnvMetricsBind, "127.0.0.1:10001")
	t.Setenv(EnvLogLevel, "debug")
	t.Setenv(EnvWAFProfilesPath, profilesPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.GRPCBind != "127.0.0.1:10000" {
		t.Fatalf("unexpected grpc bind: %q", cfg.GRPCBind)
	}
	if cfg.MetricsBind != "127.0.0.1:10001" {
		t.Fatalf("unexpected metrics bind: %q", cfg.MetricsBind)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Fatalf("unexpected log level: %v", cfg.LogLevel)
	}
	if cfg.DefaultProfile != "strict" {
		t.Fatalf("unexpected default profile: %q", cfg.DefaultProfile)
	}

	profile := cfg.Profiles["strict"]
	if profile.Mode != model.ModeBlock {
		t.Fatalf("unexpected mode: %q", profile.Mode)
	}
	if profile.RequestBodyLimit != 4096 {
		t.Fatalf("unexpected request body limit: %d", profile.RequestBodyLimit)
	}
	if profile.ResponseBodyLimit != 8192 {
		t.Fatalf("unexpected response body limit: %d", profile.ResponseBodyLimit)
	}
	if !reflect.DeepEqual(profile.ResponseBodyMIMETypes, []string{"application/json", "text/plain"}) {
		t.Fatalf("unexpected response body mime types: %+v", profile.ResponseBodyMIMETypes)
	}
	if !reflect.DeepEqual(profile.ExcludedRuleIDs, []int{941130, 942100}) {
		t.Fatalf("unexpected excluded rule ids: %+v", profile.ExcludedRuleIDs)
	}
	if profile.InboundAnomalyThreshold == nil || *profile.InboundAnomalyThreshold != 9 {
		t.Fatalf("unexpected inbound threshold: %+v", profile.InboundAnomalyThreshold)
	}
	if profile.OutboundAnomalyThreshold == nil || *profile.OutboundAnomalyThreshold != 7 {
		t.Fatalf("unexpected outbound threshold: %+v", profile.OutboundAnomalyThreshold)
	}
	if profile.OnError.Default != model.ErrorPolicyAllow {
		t.Fatalf("unexpected on_error default: %q", profile.OnError.Default)
	}
	if profile.OnError.Resolve(model.ActionRequestBody) != model.ErrorPolicyDeny {
		t.Fatalf("unexpected request body policy: %q", profile.OnError.Resolve(model.ActionRequestBody))
	}
	if profile.OnError.Resolve(model.ActionResponseBody) != model.ErrorPolicyAllow {
		t.Fatalf("unexpected response body policy: %q", profile.OnError.Resolve(model.ActionResponseBody))
	}
	if profile.OnError.Resolve(model.ActionRequestHeaders) != model.ErrorPolicyAllow {
		t.Fatalf("unexpected inherited request headers policy: %q", profile.OnError.Resolve(model.ActionRequestHeaders))
	}
}

func TestLoadRequiresProfilesPath(t *testing.T) {
	t.Setenv(EnvWAFProfilesPath, "")
	if _, err := Load(); err == nil {
		t.Fatal("expected missing WAF_PROFILES_PATH error")
	}
}

func TestLoadFailsWhenDefaultProfileMissing(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
profiles:
  strict:
    mode: block
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected missing default_profile error")
	}
}

func TestLoadFailsWhenDefaultProfileUnknown(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: missing
profiles:
  strict:
    mode: block
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected unknown default_profile error")
	}
}

func TestLoadInvalidModeFails(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    mode: aggressive
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestLoadInvalidRuleIDFails(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    mode: block
    excluded_rule_ids: [941130, -1]
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid excluded rule id error")
	}
}

func TestLoadInvalidThresholdFails(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    mode: block
    inbound_anomaly_score_threshold: -1
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid threshold error")
	}
}

func TestLoadInvalidOnErrorFails(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    mode: block
    on_error:
      request_headers: continue
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid on_error value error")
	}
}

func TestLoadInvalidResponseBodyMIMETypeFails(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    mode: block
    response_body_mime_types:
      - ""
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid response_body_mime_types error")
	}
}

func TestLoadLegacyBehaviorEnvVarsDoNotAffectProfiles(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    mode: block
`)

	t.Setenv(EnvWAFProfilesPath, profilesPath)
	t.Setenv("WAF_MODE", "detect")
	t.Setenv("WAF_ON_ERROR_DEFAULT", "allow")
	t.Setenv("WAF_EXCLUDED_RULE_IDS", "942100")
	t.Setenv("WAF_INBOUND_ANOMALY_SCORE_THRESHOLD", "99")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Profiles["strict"].Mode != model.ModeBlock {
		t.Fatalf("expected profile mode from yaml, got %q", cfg.Profiles["strict"].Mode)
	}
	if cfg.Profiles["strict"].OnError.Default != model.ErrorPolicyDeny {
		t.Fatalf("expected on_error default from yaml parsing defaults, got %q", cfg.Profiles["strict"].OnError.Default)
	}
}

func writeProfilesFile(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o644); err != nil {
		t.Fatalf("write profiles file: %v", err)
	}
	return path
}
