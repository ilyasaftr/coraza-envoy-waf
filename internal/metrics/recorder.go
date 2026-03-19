package metrics

import (
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
	"github.com/prometheus/client_golang/prometheus"
)

type PrometheusRecorder struct {
	requests      *prometheus.CounterVec
	interruptions prometheus.Counter
	failures      prometheus.Counter
}

func NewPrometheusRecorder(registerer prometheus.Registerer) (*PrometheusRecorder, error) {
	recorder := &PrometheusRecorder{
		requests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "coraza_ext_proc_requests_total",
				Help: "Total ext_proc requests by decision.",
			},
			[]string{"decision"},
		),
		interruptions: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "coraza_ext_proc_interruptions_total",
				Help: "Total Coraza interruptions.",
			},
		),
		failures: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "coraza_ext_proc_failures_total",
				Help: "Total ext_proc internal failures.",
			},
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

func (r *PrometheusRecorder) Record(_ model.Request, result model.Result) {
	decision := string(result.Decision)
	if decision == "" {
		decision = string(model.DecisionAllow)
	}
	r.requests.WithLabelValues(decision).Inc()

	if result.Interruption != nil {
		r.interruptions.Inc()
	}

	if result.Decision == model.DecisionError || result.Err != nil {
		r.failures.Inc()
	}
}

type NoopRecorder struct{}

func (NoopRecorder) Record(_ model.Request, _ model.Result) {}
