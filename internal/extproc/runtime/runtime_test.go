package runtime

import (
	"strings"
	"testing"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func TestNormalizeProfilesValidation(t *testing.T) {
	validProfiles := map[string]ProfileRuntime{
		"default": {
			NewSession: stubSessionFactory,
		},
	}

	tests := []struct {
		name          string
		profiles      map[string]ProfileRuntime
		defaultName   string
		expectErrPart string
	}{
		{
			name:          "empty default profile",
			profiles:      validProfiles,
			defaultName:   "",
			expectErrPart: "default profile is required",
		},
		{
			name:          "empty profile map",
			profiles:      map[string]ProfileRuntime{},
			defaultName:   "default",
			expectErrPart: "at least one profile runtime is required",
		},
		{
			name: "empty profile key",
			profiles: map[string]ProfileRuntime{
				"  ": {NewSession: stubSessionFactory},
			},
			defaultName:   "default",
			expectErrPart: "profile name must not be empty",
		},
		{
			name: "missing session factory",
			profiles: map[string]ProfileRuntime{
				"default": {},
			},
			defaultName:   "default",
			expectErrPart: `profile "default" session factory is required`,
		},
		{
			name: "default missing from profiles",
			profiles: map[string]ProfileRuntime{
				"strict": {NewSession: stubSessionFactory},
			},
			defaultName:   "default",
			expectErrPart: `default profile "default" does not exist`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := NormalizeProfiles(tt.profiles, tt.defaultName)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectErrPart)
			}
			if !strings.Contains(err.Error(), tt.expectErrPart) {
				t.Fatalf("expected error containing %q, got %q", tt.expectErrPart, err.Error())
			}
		})
	}
}

func TestNormalizeProfilesSuccessNormalizesFields(t *testing.T) {
	normalized, defaultName, err := NormalizeProfiles(
		map[string]ProfileRuntime{
			"default": {
				Mode:       model.Mode(""),
				OnError:    model.OnErrorPolicy{},
				NewSession: stubSessionFactory,
			},
		},
		" default ",
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if defaultName != "default" {
		t.Fatalf("expected trimmed default name, got %q", defaultName)
	}

	runtime := normalized["default"]
	if runtime.Name != "default" {
		t.Fatalf("expected runtime name default, got %q", runtime.Name)
	}
	if runtime.Mode != model.ModeBlock {
		t.Fatalf("expected mode fallback block, got %q", runtime.Mode)
	}
	if runtime.OnError.Default != model.ErrorPolicyDeny {
		t.Fatalf("expected on_error default deny, got %q", runtime.OnError.Default)
	}
	if runtime.OnError.Overrides == nil {
		t.Fatal("expected overrides map to be initialized")
	}

	threshold := runtime.ThresholdForAction(model.ActionRequestHeaders)
	if threshold.Source != model.ThresholdSourceUnknown {
		t.Fatalf("expected threshold source unknown, got %q", threshold.Source)
	}
}

func TestNormalizeMode(t *testing.T) {
	if got := NormalizeMode(model.ModeDetect); got != model.ModeDetect {
		t.Fatalf("expected detect mode, got %q", got)
	}
	if got := NormalizeMode(model.Mode("invalid")); got != model.ModeBlock {
		t.Fatalf("expected invalid mode fallback to block, got %q", got)
	}
}

func TestNormalizeOnErrorPolicy(t *testing.T) {
	normalized := NormalizeOnErrorPolicy(model.OnErrorPolicy{})
	if normalized.Default != model.ErrorPolicyDeny {
		t.Fatalf("expected default deny, got %q", normalized.Default)
	}
	if normalized.Overrides == nil {
		t.Fatal("expected overrides map to be initialized")
	}
}

func stubSessionFactory(model.Request) Session {
	return stubSession{}
}

type stubSession struct{}

func (stubSession) ProcessRequestHeaders() model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (stubSession) ProcessRequestBodyChunk([]byte, bool) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (stubSession) ProcessResponseHeaders(int, string, []model.Header) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (stubSession) ProcessResponseBodyChunk([]byte, bool) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (stubSession) Close() {}
