package observe

import (
	"context"
	"log/slog"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/pipeline"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func LogFinalResult(
	logger *slog.Logger,
	request model.Request,
	profileName string,
	finalResult model.Result,
	outcomes []pipeline.ActionOutcome,
) {
	if logger == nil {
		return
	}

	ctx := context.Background()
	interesting := hasInterestingOutcome(finalResult, outcomes)
	debugEnabled := logger.Enabled(ctx, slog.LevelDebug)
	if !interesting && !debugEnabled {
		return
	}

	actionResults := make([]map[string]any, 0, len(outcomes))
	for _, item := range outcomes {
		entry := map[string]any{
			"action":           string(item.Action),
			"decision":         string(item.Decision),
			"interrupted":      item.Interrupted,
			"on_error_policy":  string(item.OnErrorPolicy),
			"threshold_source": string(item.ThresholdSource),
		}
		if item.HTTPStatusCode > 0 {
			entry["http_status"] = item.HTTPStatusCode
		}
		if item.RuleID != "" {
			entry["rule_id"] = item.RuleID
		}
		if item.Error != "" {
			entry["error"] = item.Error
		}
		if item.AnomalyScore != nil {
			entry["anomaly_score"] = *item.AnomalyScore
		}
		if item.Threshold != nil {
			entry["threshold"] = *item.Threshold
		}
		actionResults = append(actionResults, entry)
	}

	fields := []any{
		"request_id", request.ID,
		"profile", profileName,
		"host", request.Host,
		"path", request.Path,
		"method", request.Method,
		"mode", request.Mode,
		"final_decision", finalResult.Decision,
		"action_results", actionResults,
	}
	if finalResult.HTTPStatusCode > 0 {
		fields = append(fields, "final_status", finalResult.HTTPStatusCode)
	}
	if finalResult.Err != nil {
		fields = append(fields, "final_error", finalResult.Err.Error())
	}
	if interesting {
		logger.Info("coraza ext_proc request summary", fields...)
		return
	}
	logger.Debug("coraza ext_proc request summary", fields...)
}

func hasInterestingOutcome(finalResult model.Result, outcomes []pipeline.ActionOutcome) bool {
	if finalResult.Decision != model.DecisionAllow || finalResult.Err != nil {
		return true
	}
	for _, outcome := range outcomes {
		if outcome.Interrupted || outcome.Error != "" {
			return true
		}
		if outcome.Decision == model.DecisionDeny || outcome.Decision == model.DecisionError {
			return true
		}
	}
	return false
}
