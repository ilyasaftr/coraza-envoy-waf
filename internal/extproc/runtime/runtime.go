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
	EngineMode         model.EngineMode
	NewSession         func(req model.Request) Session
	ThresholdForAction func(action model.ProcessingAction) model.ThresholdInfo
}

func NewProfileRuntime(name string, evaluator *waf.Evaluator, engineMode model.EngineMode) (ProfileRuntime, error) {
	if evaluator == nil {
		return ProfileRuntime{}, errors.New("evaluator is required")
	}

	runtime := ProfileRuntime{
		Name:       strings.TrimSpace(name),
		EngineMode: NormalizeEngineMode(engineMode),
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
		runtime.EngineMode = NormalizeEngineMode(runtime.EngineMode)
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

func NormalizeEngineMode(mode model.EngineMode) model.EngineMode {
	switch mode {
	case model.EngineModeDetect:
		return model.EngineModeDetect
	case model.EngineModeBlock:
		return model.EngineModeBlock
	case model.EngineModeOff:
		return model.EngineModeOff
	default:
		return model.EngineModeBlock
	}
}
