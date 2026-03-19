package metrics

import (
	"errors"
	"strings"
	"testing"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestPrometheusRecorderUsesDecisionOnlyAndUnlabeledInterruptions(t *testing.T) {
	registry := prometheus.NewRegistry()
	recorder, err := NewPrometheusRecorder(registry)
	if err != nil {
		t.Fatalf("new prometheus recorder: %v", err)
	}

	recorder.Record(model.Request{}, model.Result{Decision: model.DecisionAllow})
	recorder.Record(model.Request{}, model.Result{
		Decision: model.DecisionDeny,
		Interruption: &model.Interruption{
			RuleID: 942100,
		},
	})
	recorder.Record(model.Request{}, model.Result{
		Decision: model.DecisionError,
		Err:      errors.New("ignored"),
	})

	expected := `
# HELP coraza_ext_proc_requests_total Total ext_proc requests by decision.
# TYPE coraza_ext_proc_requests_total counter
coraza_ext_proc_requests_total{decision="allow"} 1
coraza_ext_proc_requests_total{decision="deny"} 1
coraza_ext_proc_requests_total{decision="error"} 1
# HELP coraza_ext_proc_interruptions_total Total Coraza interruptions.
# TYPE coraza_ext_proc_interruptions_total counter
coraza_ext_proc_interruptions_total 1
# HELP coraza_ext_proc_failures_total Total ext_proc internal failures.
# TYPE coraza_ext_proc_failures_total counter
coraza_ext_proc_failures_total 1
`

	if err := testutil.GatherAndCompare(registry, strings.NewReader(expected),
		"coraza_ext_proc_requests_total",
		"coraza_ext_proc_interruptions_total",
		"coraza_ext_proc_failures_total",
	); err != nil {
		t.Fatalf("unexpected metrics output: %v", err)
	}
}
