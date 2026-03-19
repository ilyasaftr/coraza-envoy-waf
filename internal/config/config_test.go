package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func TestLoadDefaultsFromProfilesYAML(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: default
profiles:
  default:
    directives: |
      Include @coraza.conf-recommended
      SecRuleEngine On
      Include @owasp_crs/*.conf
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
	if cfg.GRPCStreamWorkers != 0 {
		t.Fatalf("unexpected grpc stream workers: %d", cfg.GRPCStreamWorkers)
	}
	if cfg.DefaultProfile != "default" {
		t.Fatalf("unexpected default profile: %q", cfg.DefaultProfile)
	}

	profile := cfg.Profiles["default"]
	if profile.EngineMode != model.EngineModeBlock {
		t.Fatalf("unexpected mode: %q", profile.EngineMode)
	}
	if !strings.Contains(profile.Directives, "SecRuleEngine On") {
		t.Fatalf("expected directives to be preserved, got: %s", profile.Directives)
	}
}

func TestLoadCustomDirectivesDeriveDetectionOnlyMode(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    directives: |
      Include @coraza.conf-recommended
      SecRuleEngine DetectionOnly
      Include @crs-setup.conf.example
      SecAction "id:10000001,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=9"
      Include @owasp_crs/*.conf
`)

	t.Setenv(EnvGRPCBind, "127.0.0.1:10000")
	t.Setenv(EnvMetricsBind, "127.0.0.1:10001")
	t.Setenv(EnvLogLevel, "debug")
	t.Setenv(EnvGRPCNumStreamWorkers, "4")
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
	if cfg.GRPCStreamWorkers != 4 {
		t.Fatalf("unexpected grpc stream workers: %d", cfg.GRPCStreamWorkers)
	}

	profile := cfg.Profiles["strict"]
	if profile.EngineMode != model.EngineModeDetect {
		t.Fatalf("unexpected mode: %q", profile.EngineMode)
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
    directives: |
      SecRuleEngine On
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
    directives: |
      SecRuleEngine On
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected unknown default_profile error")
	}
}

func TestLoadMissingDirectivesFails(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict: {}
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected missing directives error")
	}
}

func TestLoadMissingSecRuleEngineFails(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    directives: |
      Include @coraza.conf-recommended
      Include @owasp_crs/*.conf
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected missing SecRuleEngine error")
	}
}

func TestLoadMultipleSecRuleEngineFails(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    directives: |
      SecRuleEngine DetectionOnly
      SecRuleEngine On
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected duplicate SecRuleEngine error")
	}
}

func TestLoadInvalidSecRuleEngineFails(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    directives: |
      SecRuleEngine Aggressive
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid SecRuleEngine error")
	}
}

func TestLoadInvalidGRPCNumStreamWorkersFails(t *testing.T) {
	profilesPath := writeProfilesFile(t, `
default_profile: strict
profiles:
  strict:
    directives: |
      SecRuleEngine On
`)
	t.Setenv(EnvWAFProfilesPath, profilesPath)
	t.Setenv(EnvGRPCNumStreamWorkers, "-1")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid grpc num stream workers error")
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
