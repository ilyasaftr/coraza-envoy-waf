package pipeline

import (
	"errors"
	"testing"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/runtime"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func TestFinalizeActionHardcodedFailOpenContinues(t *testing.T) {
	state := newState()

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
	outcomes := state.Outcomes()
	if len(outcomes) != 1 || outcomes[0].Error == "" {
		t.Fatalf("expected error outcome to be recorded, got %+v", outcomes)
	}
}

func TestNewStreamStatePreallocatesOutcomes(t *testing.T) {
	state := newState()
	outcomes := state.Outcomes()
	if len(outcomes) != 0 {
		t.Fatalf("expected outcomes length 0, got %d", len(outcomes))
	}
	if cap(outcomes) != defaultActionOutcomesCapacity {
		t.Fatalf("expected outcomes capacity %d, got %d", defaultActionOutcomesCapacity, cap(outcomes))
	}
}

func TestFinalizeActionUnknownKeepsError(t *testing.T) {
	state := newState()

	resolved := state.FinalizeAction(model.ActionUnknown, model.Result{
		Decision:       model.DecisionError,
		HTTPStatusCode: 503,
		Err:            errors.New("unsupported message"),
	})

	if resolved.Decision != model.DecisionError {
		t.Fatalf("expected error decision, got %q", resolved.Decision)
	}
	if resolved.HTTPStatusCode != 503 {
		t.Fatalf("expected status 503, got %d", resolved.HTTPStatusCode)
	}
}

func TestCaptureResultPrefersDeny(t *testing.T) {
	state := newState()

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

func TestMarkRequestBodyFastPathMarksRequestComplete(t *testing.T) {
	state := newState()
	state.MarkRequestBodyFastPath("bodyless_safe_method")

	if !state.RequestComplete() {
		t.Fatal("expected request body to be marked as complete")
	}

	outcomes := state.Outcomes()
	if len(outcomes) != 1 {
		t.Fatalf("expected one outcome, got %d", len(outcomes))
	}
	if outcomes[0].Action != model.ActionRequestBody {
		t.Fatalf("expected request_body outcome, got %q", outcomes[0].Action)
	}
	if outcomes[0].FastPathReason != "bodyless_safe_method" {
		t.Fatalf("expected fast path reason bodyless_safe_method, got %q", outcomes[0].FastPathReason)
	}
}

func newState() *StreamState {
	return NewStreamState("default", runtime.ProfileRuntime{
		Name: "default",
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
