package runtime

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/waf"
)

type Session interface {
	ProcessRequestHeaders() model.Result
	ProcessRequestBodyChunk(body []byte, endOfStream bool) model.Result
	ProcessResponseHeaders(statusCode int, protocol string, headers []model.Header) model.Result
	ProcessResponseBodyChunk(body []byte, endOfStream bool) model.Result
	Close()
}

type ProfileRuntime struct {
	Name               string
	Mode               model.Mode
	OnError            model.OnErrorPolicy
	NewSession         func(req model.Request) Session
	ThresholdForAction func(action model.ProcessingAction) model.ThresholdInfo
}

func NewProfileRuntime(name string, evaluator *waf.Evaluator, mode model.Mode, onError model.OnErrorPolicy) (ProfileRuntime, error) {
	if evaluator == nil {
		return ProfileRuntime{}, errors.New("evaluator is required")
	}

	runtime := ProfileRuntime{
		Name:    strings.TrimSpace(name),
		Mode:    NormalizeMode(mode),
		OnError: NormalizeOnErrorPolicy(onError),
		NewSession: func(req model.Request) Session {
			return evaluator.NewSession(req)
		},
		ThresholdForAction: evaluator.ThresholdForAction,
	}
	if runtime.Name == "" {
		return ProfileRuntime{}, errors.New("profile name is required")
	}
	return runtime, nil
}

func NormalizeProfiles(profiles map[string]ProfileRuntime, defaultProfile string) (map[string]ProfileRuntime, string, error) {
	defaultName := strings.TrimSpace(defaultProfile)
	if defaultName == "" {
		return nil, "", errors.New("default profile is required")
	}
	if len(profiles) == 0 {
		return nil, "", errors.New("at least one profile runtime is required")
	}

	normalized := make(map[string]ProfileRuntime, len(profiles))
	for name, runtime := range profiles {
		profileName := strings.TrimSpace(name)
		if profileName == "" {
			return nil, "", errors.New("profile name must not be empty")
		}
		if runtime.NewSession == nil {
			return nil, "", fmt.Errorf("profile %q session factory is required", profileName)
		}
		if runtime.Name == "" {
			runtime.Name = profileName
		}
		runtime.Mode = NormalizeMode(runtime.Mode)
		runtime.OnError = NormalizeOnErrorPolicy(runtime.OnError)
		if runtime.ThresholdForAction == nil {
			runtime.ThresholdForAction = func(model.ProcessingAction) model.ThresholdInfo {
				return model.ThresholdInfo{Source: model.ThresholdSourceUnknown}
			}
		}
		normalized[profileName] = runtime
	}

	if _, ok := normalized[defaultName]; !ok {
		return nil, "", fmt.Errorf("default profile %q does not exist", defaultName)
	}

	return normalized, defaultName, nil
}

func NormalizeMode(mode model.Mode) model.Mode {
	switch mode {
	case model.ModeDetect:
		return model.ModeDetect
	case model.ModeBlock:
		return model.ModeBlock
	default:
		return model.ModeBlock
	}
}

func NormalizeOnErrorPolicy(policy model.OnErrorPolicy) model.OnErrorPolicy {
	if policy.Default == "" {
		policy.Default = model.ErrorPolicyDeny
	}
	if policy.Overrides == nil {
		policy.Overrides = map[model.ProcessingAction]model.ErrorPolicy{}
	}
	return policy
}
