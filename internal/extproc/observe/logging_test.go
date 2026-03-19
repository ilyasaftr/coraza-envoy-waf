package observe

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/pipeline"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func TestLogFinalResultDenyOutcome(t *testing.T) {
	handler := &captureHandler{minLevel: slog.LevelInfo}
	logger := slog.New(handler)

	anomaly := 10
	threshold := 5
	LogFinalResult(
		logger,
		model.Request{
			ID:     "req-1",
			Host:   "podinfo.klawu.com",
			Path:   "/",
			Method: "GET",
		},
		"strict",
		model.EngineModeBlock,
		model.Result{
			Decision:       model.DecisionDeny,
			HTTPStatusCode: 403,
		},
		[]pipeline.ActionOutcome{
			{
				Action:          model.ActionRequestHeaders,
				Decision:        model.DecisionDeny,
				HTTPStatusCode:  403,
				Interrupted:     true,
				RuleID:          "942100",
				AnomalyScore:    &anomaly,
				Threshold:       &threshold,
				ThresholdSource: model.ThresholdSourceProfileDirective,
			},
		},
	)

	entry := handler.last()
	if entry.message != "coraza ext_proc request summary" {
		t.Fatalf("unexpected log message: %q", entry.message)
	}
	if got := entry.attrs["final_status"]; got != int64(403) {
		t.Fatalf("expected final_status 403, got %#v", got)
	}
	actionResults, ok := entry.attrs["action_results"].([]map[string]any)
	if !ok || len(actionResults) != 1 {
		t.Fatalf("expected one action result, got %#v", entry.attrs["action_results"])
	}
	if got := actionResults[0]["rule_id"]; got != "942100" {
		t.Fatalf("expected rule_id 942100, got %#v", got)
	}
	if got := actionResults[0]["anomaly_score"]; got != 10 {
		t.Fatalf("expected anomaly_score 10, got %#v", got)
	}
	if got := actionResults[0]["threshold"]; got != 5 {
		t.Fatalf("expected threshold 5, got %#v", got)
	}
}

func TestLogFinalResultAllowOutcome(t *testing.T) {
	handler := &captureHandler{minLevel: slog.LevelInfo}
	logger := slog.New(handler)

	LogFinalResult(
		logger,
		model.Request{
			ID:     "req-allow",
			Host:   "podinfo.klawu.com",
			Path:   "/healthz",
			Method: "GET",
		},
		"default",
		model.EngineModeDetect,
		model.Result{
			Decision: model.DecisionAllow,
		},
		[]pipeline.ActionOutcome{
			{
				Action:          model.ActionRequestHeaders,
				Decision:        model.DecisionAllow,
				Interrupted:     false,
				ThresholdSource: model.ThresholdSourceUnknown,
			},
		},
	)

	if got := len(handler.entries); got != 0 {
		t.Fatalf("expected no info log entries for normal allow path, got %d", got)
	}
}

func TestLogFinalResultAllowOutcomeDebug(t *testing.T) {
	handler := &captureHandler{minLevel: slog.LevelDebug}
	logger := slog.New(handler)

	LogFinalResult(
		logger,
		model.Request{
			ID:     "req-allow-debug",
			Host:   "podinfo.klawu.com",
			Path:   "/healthz",
			Method: "GET",
		},
		"default",
		model.EngineModeDetect,
		model.Result{
			Decision: model.DecisionAllow,
		},
		[]pipeline.ActionOutcome{
			{
				Action:          model.ActionRequestHeaders,
				Decision:        model.DecisionAllow,
				Interrupted:     false,
				ThresholdSource: model.ThresholdSourceUnknown,
			},
		},
	)

	if got := len(handler.entries); got != 1 {
		t.Fatalf("expected one debug entry, got %d", got)
	}
	entry := handler.last()
	if entry.level != slog.LevelDebug {
		t.Fatalf("expected debug level entry, got %s", entry.level.String())
	}
	if _, exists := entry.attrs["action_results"]; !exists {
		t.Fatalf("expected action_results in debug summary, got %#v", entry.attrs)
	}
}

func TestLogFinalResultErrorOutcome(t *testing.T) {
	handler := &captureHandler{minLevel: slog.LevelInfo}
	logger := slog.New(handler)

	LogFinalResult(
		logger,
		model.Request{
			ID:     "req-error",
			Host:   "podinfo.klawu.com",
			Path:   "/api",
			Method: "POST",
		},
		"strict",
		model.EngineModeBlock,
		model.Result{
			Decision: model.DecisionAllow,
			Err:      errors.New("synthetic processor failure"),
		},
		[]pipeline.ActionOutcome{
			{
				Action:          model.ActionRequestBody,
				Decision:        model.DecisionAllow,
				Error:           "synthetic processor failure",
				ThresholdSource: model.ThresholdSourceUnknown,
			},
		},
	)

	entry := handler.last()
	if _, exists := entry.attrs["final_status"]; exists {
		t.Fatalf("did not expect final_status for hardcoded fail-open error, got %#v", entry.attrs["final_status"])
	}
	if got := entry.attrs["final_error"]; got != "synthetic processor failure" {
		t.Fatalf("expected final_error, got %#v", got)
	}
}

type capturedLog struct {
	message string
	level   slog.Level
	attrs   map[string]any
}

type captureHandler struct {
	minLevel slog.Level
	entries  []capturedLog
}

func (h *captureHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.minLevel
}

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	entry := capturedLog{
		message: record.Message,
		level:   record.Level,
		attrs:   map[string]any{},
	}
	record.Attrs(func(attr slog.Attr) bool {
		entry.attrs[attr.Key] = attrValue(attr.Value)
		return true
	})
	h.entries = append(h.entries, entry)
	return nil
}

func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *captureHandler) WithGroup(_ string) slog.Handler {
	return h
}

func (h *captureHandler) last() capturedLog {
	if len(h.entries) == 0 {
		return capturedLog{}
	}
	return h.entries[len(h.entries)-1]
}

func attrValue(value slog.Value) any {
	switch value.Kind() {
	case slog.KindString:
		return value.String()
	case slog.KindInt64:
		return value.Int64()
	case slog.KindUint64:
		return value.Uint64()
	case slog.KindBool:
		return value.Bool()
	case slog.KindFloat64:
		return value.Float64()
	case slog.KindAny:
		return value.Any()
	default:
		return value.Any()
	}
}
