package config

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
	yaml "go.yaml.in/yaml/v2"
)

const (
	defaultGRPCBind = ":9002"
	defaultHTTPBind = ":9090"
	defaultBodySize = 1048576
)

const (
	EnvGRPCBind        = "GRPC_BIND"
	EnvMetricsBind     = "METRICS_BIND"
	EnvLogLevel        = "LOG_LEVEL"
	EnvWAFProfilesPath = "WAF_PROFILES_PATH"
)

type Config struct {
	GRPCBind       string
	MetricsBind    string
	LogLevel       slog.Level
	ProfilesPath   string
	DefaultProfile string
	Profiles       map[string]Profile
}

type Profile struct {
	Name                     string
	Mode                     model.Mode
	RequestBodyLimit         int
	ResponseBodyLimit        int
	ResponseBodyMIMETypes    []string
	ExcludedRuleIDs          []int
	InboundAnomalyThreshold  *int
	OutboundAnomalyThreshold *int
	OnError                  model.OnErrorPolicy
}

type profilesFile struct {
	DefaultProfile string                `yaml:"default_profile"`
	Profiles       map[string]rawProfile `yaml:"profiles"`
}

type rawProfile struct {
	Mode                     string     `yaml:"mode"`
	ExcludedRuleIDs          []int      `yaml:"excluded_rule_ids"`
	InboundAnomalyThreshold  *int       `yaml:"inbound_anomaly_score_threshold"`
	OutboundAnomalyThreshold *int       `yaml:"outbound_anomaly_score_threshold"`
	RequestBodyLimitBytes    *int       `yaml:"request_body_limit_bytes"`
	ResponseBodyLimitBytes   *int       `yaml:"response_body_limit_bytes"`
	ResponseBodyMIMETypes    []string   `yaml:"response_body_mime_types"`
	OnError                  rawOnError `yaml:"on_error"`
}

type rawOnError struct {
	Default         string `yaml:"default"`
	RequestHeaders  string `yaml:"request_headers"`
	RequestBody     string `yaml:"request_body"`
	ResponseHeaders string `yaml:"response_headers"`
	ResponseBody    string `yaml:"response_body"`
}

func Load() (Config, error) {
	cfg := Config{
		GRPCBind:     envOrDefault(EnvGRPCBind, defaultGRPCBind),
		MetricsBind:  envOrDefault(EnvMetricsBind, defaultHTTPBind),
		LogLevel:     parseLevel(envOrDefault(EnvLogLevel, "INFO")),
		ProfilesPath: strings.TrimSpace(os.Getenv(EnvWAFProfilesPath)),
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
	mode, err := parseMode(raw.Mode)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles.%s.mode: %w", name, err)
	}

	excludedRuleIDs, err := normalizeRuleIDs(raw.ExcludedRuleIDs)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles.%s.excluded_rule_ids: %w", name, err)
	}

	inboundThreshold, err := normalizeOptionalPositiveInt(raw.InboundAnomalyThreshold)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles.%s.inbound_anomaly_score_threshold: %w", name, err)
	}

	outboundThreshold, err := normalizeOptionalPositiveInt(raw.OutboundAnomalyThreshold)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles.%s.outbound_anomaly_score_threshold: %w", name, err)
	}

	requestBodyLimit, err := normalizeBodyLimit(raw.RequestBodyLimitBytes)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles.%s.request_body_limit_bytes: %w", name, err)
	}

	responseBodyLimit, err := normalizeBodyLimit(raw.ResponseBodyLimitBytes)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles.%s.response_body_limit_bytes: %w", name, err)
	}

	responseBodyMIMETypes, err := normalizeMIMETypes(raw.ResponseBodyMIMETypes)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles.%s.response_body_mime_types: %w", name, err)
	}

	onError, err := normalizeOnError(raw.OnError)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles.%s.on_error: %w", name, err)
	}

	return Profile{
		Name:                     name,
		Mode:                     mode,
		RequestBodyLimit:         requestBodyLimit,
		ResponseBodyLimit:        responseBodyLimit,
		ResponseBodyMIMETypes:    responseBodyMIMETypes,
		ExcludedRuleIDs:          excludedRuleIDs,
		InboundAnomalyThreshold:  inboundThreshold,
		OutboundAnomalyThreshold: outboundThreshold,
		OnError:                  onError,
	}, nil
}

func normalizeOnError(raw rawOnError) (model.OnErrorPolicy, error) {
	defaultPolicy := model.ErrorPolicyDeny
	if strings.TrimSpace(raw.Default) != "" {
		parsed, err := parseErrorPolicy(raw.Default)
		if err != nil {
			return model.OnErrorPolicy{}, fmt.Errorf("default: %w", err)
		}
		defaultPolicy = parsed
	}

	onError := model.OnErrorPolicy{
		Default:   defaultPolicy,
		Overrides: map[model.ProcessingAction]model.ErrorPolicy{},
	}

	type overrideEntry struct {
		raw    string
		action model.ProcessingAction
	}
	for _, entry := range []overrideEntry{
		{raw: raw.RequestHeaders, action: model.ActionRequestHeaders},
		{raw: raw.RequestBody, action: model.ActionRequestBody},
		{raw: raw.ResponseHeaders, action: model.ActionResponseHeaders},
		{raw: raw.ResponseBody, action: model.ActionResponseBody},
	} {
		if strings.TrimSpace(entry.raw) == "" {
			continue
		}
		parsed, err := parseErrorPolicy(entry.raw)
		if err != nil {
			return model.OnErrorPolicy{}, fmt.Errorf("%s: %w", entry.action, err)
		}
		onError.Overrides[entry.action] = parsed
	}
	return onError, nil
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

func parseMode(raw string) (model.Mode, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return model.ModeBlock, nil
	}
	switch value {
	case string(model.ModeDetect):
		return model.ModeDetect, nil
	case string(model.ModeBlock):
		return model.ModeBlock, nil
	default:
		return "", fmt.Errorf("must be detect or block")
	}
}

func normalizeRuleIDs(input []int) ([]int, error) {
	if len(input) == 0 {
		return nil, nil
	}

	seen := map[int]struct{}{}
	ruleIDs := make([]int, 0, len(input))
	for _, ruleID := range input {
		if ruleID <= 0 {
			return nil, fmt.Errorf("rule ids must be positive integers")
		}
		if _, ok := seen[ruleID]; ok {
			continue
		}
		seen[ruleID] = struct{}{}
		ruleIDs = append(ruleIDs, ruleID)
	}
	slices.Sort(ruleIDs)
	return ruleIDs, nil
}

func normalizeOptionalPositiveInt(value *int) (*int, error) {
	if value == nil {
		return nil, nil
	}
	if *value <= 0 {
		return nil, fmt.Errorf("must be a positive integer")
	}
	return cloneIntPointer(value), nil
}

func normalizeBodyLimit(value *int) (int, error) {
	if value == nil {
		return defaultBodySize, nil
	}
	if *value <= 0 {
		return 0, fmt.Errorf("must be a positive integer")
	}
	return *value, nil
}

func normalizeMIMETypes(input []string) ([]string, error) {
	if len(input) == 0 {
		return nil, nil
	}

	seen := map[string]struct{}{}
	types := make([]string, 0, len(input))
	for _, raw := range input {
		mimeType := strings.ToLower(strings.TrimSpace(raw))
		if mimeType == "" {
			return nil, fmt.Errorf("mime types must not be empty")
		}
		if strings.ContainsAny(mimeType, " \t\r\n") {
			return nil, fmt.Errorf("mime type %q must not contain whitespace", raw)
		}
		if _, ok := seen[mimeType]; ok {
			continue
		}
		seen[mimeType] = struct{}{}
		types = append(types, mimeType)
	}
	slices.Sort(types)
	return types, nil
}

func parseErrorPolicy(raw string) (model.ErrorPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(model.ErrorPolicyAllow):
		return model.ErrorPolicyAllow, nil
	case string(model.ErrorPolicyDeny):
		return model.ErrorPolicyDeny, nil
	default:
		return "", fmt.Errorf("must be allow or deny")
	}
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
