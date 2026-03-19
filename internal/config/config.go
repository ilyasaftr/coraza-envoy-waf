package config

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
	yaml "go.yaml.in/yaml/v2"
)

const (
	defaultGRPCBind = ":9002"
	defaultHTTPBind = ":9090"
)

const (
	EnvGRPCBind             = "GRPC_BIND"
	EnvMetricsBind          = "METRICS_BIND"
	EnvLogLevel             = "LOG_LEVEL"
	EnvGRPCNumStreamWorkers = "GRPC_NUM_STREAM_WORKERS"
	EnvWAFProfilesPath      = "WAF_PROFILES_PATH"
)

var secRuleEnginePattern = regexp.MustCompile(`(?im)^\s*SecRuleEngine\s+(On|Off|DetectionOnly)\s*(?:#.*)?$`)

type Config struct {
	GRPCBind          string
	MetricsBind       string
	LogLevel          slog.Level
	GRPCStreamWorkers uint32
	ProfilesPath      string
	DefaultProfile    string
	Profiles          map[string]Profile
}

type Profile struct {
	Name       string
	Directives string
	EngineMode model.EngineMode
}

type profilesFile struct {
	DefaultProfile string                `yaml:"default_profile"`
	Profiles       map[string]rawProfile `yaml:"profiles"`
}

type rawProfile struct {
	Directives string `yaml:"directives"`
}

func Load() (Config, error) {
	streamWorkers, err := parseNonNegativeIntEnv(EnvGRPCNumStreamWorkers)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		GRPCBind:          envOrDefault(EnvGRPCBind, defaultGRPCBind),
		MetricsBind:       envOrDefault(EnvMetricsBind, defaultHTTPBind),
		LogLevel:          parseLevel(envOrDefault(EnvLogLevel, "INFO")),
		GRPCStreamWorkers: uint32(streamWorkers),
		ProfilesPath:      strings.TrimSpace(os.Getenv(EnvWAFProfilesPath)),
	}
	if cfg.ProfilesPath == "" {
		return cfg, fmt.Errorf("%s is required", EnvWAFProfilesPath)
	}

	content, err := os.ReadFile(cfg.ProfilesPath)
	if err != nil {
		return cfg, fmt.Errorf("read profiles file: %w", err)
	}

	var raw profilesFile
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return cfg, fmt.Errorf("parse profiles yaml: %w", err)
	}

	defaultProfile := strings.TrimSpace(raw.DefaultProfile)
	if defaultProfile == "" {
		return cfg, fmt.Errorf("default_profile is required")
	}
	if len(raw.Profiles) == 0 {
		return cfg, fmt.Errorf("profiles map is required")
	}

	profiles := make(map[string]Profile, len(raw.Profiles))
	for profileName, rawProfile := range raw.Profiles {
		name := strings.TrimSpace(profileName)
		if name == "" {
			return cfg, fmt.Errorf("profile name must not be empty")
		}

		normalized, normalizeErr := normalizeProfile(name, rawProfile)
		if normalizeErr != nil {
			return cfg, normalizeErr
		}
		profiles[name] = normalized
	}
	if _, ok := profiles[defaultProfile]; !ok {
		return cfg, fmt.Errorf("default_profile %q does not exist in profiles map", defaultProfile)
	}

	cfg.DefaultProfile = defaultProfile
	cfg.Profiles = profiles
	return cfg, nil
}

func normalizeProfile(name string, raw rawProfile) (Profile, error) {
	directives := strings.TrimSpace(raw.Directives)
	if directives == "" {
		return Profile{}, fmt.Errorf("profiles.%s.directives: is required", name)
	}

	engineMode, err := parseEngineModeFromDirectives(directives)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles.%s.directives: %w", name, err)
	}

	return Profile{
		Name:       name,
		Directives: directives,
		EngineMode: engineMode,
	}, nil
}

func parseEngineModeFromDirectives(directives string) (model.EngineMode, error) {
	matches := secRuleEnginePattern.FindAllStringSubmatch(directives, -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("must include exactly one explicit SecRuleEngine directive")
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("must include exactly one explicit SecRuleEngine directive")
	}

	switch strings.ToLower(strings.TrimSpace(matches[0][1])) {
	case "on":
		return model.EngineModeBlock, nil
	case "detectiononly":
		return model.EngineModeDetect, nil
	case "off":
		return model.EngineModeOff, nil
	default:
		return "", fmt.Errorf("SecRuleEngine must be On, DetectionOnly, or Off")
	}
}

func parseLevel(raw string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func parseNonNegativeIntEnv(name string) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	if value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return value, nil
}
