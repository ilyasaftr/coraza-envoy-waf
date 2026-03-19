package metrics

import (
	"strings"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
	"github.com/prometheus/client_golang/prometheus"
)

type PrometheusRecorder struct {
	requests      *prometheus.CounterVec
	interruptions *prometheus.CounterVec
	failures      *prometheus.CounterVec
}

func NewPrometheusRecorder(registerer prometheus.Registerer) (*PrometheusRecorder, error) {
	recorder := &PrometheusRecorder{
		requests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "coraza_ext_proc_requests_total",
				Help: "Total ext_proc requests by profile and decision.",
			},
			[]string{"profile", "decision"},
		),
		interruptions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "coraza_ext_proc_interruptions_total",
				Help: "Total Coraza interruptions by profile.",
			},
			[]string{"profile"},
		),
		failures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "coraza_ext_proc_failures_total",
				Help: "Total ext_proc internal failures by profile.",
			},
			[]string{"profile"},
		),
	}

	if err := registerer.Register(recorder.requests); err != nil {
		return nil, err
	}
	if err := registerer.Register(recorder.interruptions); err != nil {
		return nil, err
	}
	if err := registerer.Register(recorder.failures); err != nil {
		return nil, err
	}

	return recorder, nil
}

func (r *PrometheusRecorder) Record(_ model.Request, profileName string, result model.Result) {
	profileName = normalizeProfileLabel(profileName)
	decision := string(result.Decision)
	if decision == "" {
		decision = string(model.DecisionAllow)
	}
	r.requests.WithLabelValues(profileName, decision).Inc()

	if result.Interruption != nil {
		r.interruptions.WithLabelValues(profileName).Inc()
	}

	if result.Decision == model.DecisionError || result.Err != nil {
		r.failures.WithLabelValues(profileName).Inc()
	}
}

type NoopRecorder struct{}

func (NoopRecorder) Record(_ model.Request, _ string, _ model.Result) {}

func normalizeProfileLabel(profileName string) string {
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return "unknown"
	}
	return profileName
}
