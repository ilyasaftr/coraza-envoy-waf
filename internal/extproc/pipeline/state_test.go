package pipeline

import (
	"errors"
	"testing"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/runtime"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func TestFinalizeActionOnErrorDenyReturns503(t *testing.T) {
	state := newStateWithOnError(model.ErrorPolicyDeny)

	resolved := state.FinalizeAction(model.ActionRequestBody, model.Result{
		Decision: model.DecisionError,
		Err:      errors.New("synthetic failure"),
	})

	if resolved.Decision != model.DecisionError {
		t.Fatalf("expected error decision, got %q", resolved.Decision)
	}
	if resolved.HTTPStatusCode != 503 {
		t.Fatalf("expected status 503, got %d", resolved.HTTPStatusCode)
	}
}

func TestFinalizeActionOnErrorAllowContinues(t *testing.T) {
	state := newStateWithOnError(model.ErrorPolicyAllow)

	resolved := state.FinalizeAction(model.ActionRequestBody, model.Result{
		Decision: model.DecisionError,
		Err:      errors.New("synthetic failure"),
	})

	if resolved.Decision != model.DecisionAllow {
		t.Fatalf("expected allow decision, got %q", resolved.Decision)
	}
	if resolved.HTTPStatusCode != 0 {
		t.Fatalf("expected cleared status code, got %d", resolved.HTTPStatusCode)
	}
}

func TestCaptureResultPrefersDeny(t *testing.T) {
	state := newStateWithOnError(model.ErrorPolicyDeny)

	state.CaptureResult(model.Result{Decision: model.DecisionAllow})
	state.CaptureResult(model.Result{Decision: model.DecisionDeny, HTTPStatusCode: 403})
	state.CaptureResult(model.Result{Decision: model.DecisionAllow})

	if state.FinalResult().Decision != model.DecisionDeny {
		t.Fatalf("expected final deny decision, got %q", state.FinalResult().Decision)
	}
}

func TestEnsureRequestBodyFinalizedRunsOnce(t *testing.T) {
	stub := &countingSession{}
	state := NewStreamState("default", runtime.ProfileRuntime{
		Name: "default",
		Mode: model.ModeBlock,
		OnError: model.OnErrorPolicy{
			Default: model.ErrorPolicyDeny,
		},
		NewSession: func(model.Request) runtime.Session {
			return stub
		},
		ThresholdForAction: func(model.ProcessingAction) model.ThresholdInfo {
			return model.ThresholdInfo{Source: model.ThresholdSourceUnknown}
		},
	})

	_, first := state.EnsureRequestBodyFinalized()
	_, second := state.EnsureRequestBodyFinalized()

	if !first {
		t.Fatal("expected first finalization to execute")
	}
	if second {
		t.Fatal("expected second finalization to be skipped")
	}
	if stub.requestBodyCalls != 1 {
		t.Fatalf("expected one request body call, got %d", stub.requestBodyCalls)
	}
}

func newStateWithOnError(policy model.ErrorPolicy) *StreamState {
	return NewStreamState("default", runtime.ProfileRuntime{
		Name: "default",
		Mode: model.ModeDetect,
		OnError: model.OnErrorPolicy{
			Default: policy,
		},
		NewSession: func(model.Request) runtime.Session {
			return noopSession{}
		},
		ThresholdForAction: func(model.ProcessingAction) model.ThresholdInfo {
			return model.ThresholdInfo{Source: model.ThresholdSourceUnknown}
		},
	})
}

type noopSession struct{}

func (noopSession) ProcessRequestHeaders() model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (noopSession) ProcessRequestBodyChunk([]byte, bool) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (noopSession) ProcessResponseHeaders(int, string, []model.Header) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (noopSession) ProcessResponseBodyChunk([]byte, bool) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (noopSession) Close() {}

type countingSession struct {
	requestBodyCalls int
}

func (s *countingSession) ProcessRequestHeaders() model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (s *countingSession) ProcessRequestBodyChunk([]byte, bool) model.Result {
	s.requestBodyCalls++
	return model.Result{Decision: model.DecisionAllow}
}

func (s *countingSession) ProcessResponseHeaders(int, string, []model.Header) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (s *countingSession) ProcessResponseBodyChunk([]byte, bool) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (s *countingSession) Close() {}
