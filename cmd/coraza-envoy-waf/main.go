package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/config"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/metrics"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/perf"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/server"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/waf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	slog.SetDefault(logger)

	// Register optional RE2/libinjection implementations before any WAF is constructed.
	perf.Register()

	registry := prometheus.NewRegistry()
	recorder, err := metrics.NewPrometheusRecorder(registry)
	if err != nil {
		logger.Error("failed to initialize metrics recorder", "error", err)
		os.Exit(1)
	}

	runtimes, err := buildProfileRuntimes(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize profile runtimes", "error", err)
		os.Exit(1)
	}

	extProcService, err := extproc.NewService(runtimes, cfg.DefaultProfile, recorder, logger)
	if err != nil {
		logger.Error("failed to initialize ext_proc service", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	app := server.New(
		cfg.GRPCBind,
		cfg.MetricsBind,
		extProcService,
		mux,
		logger,
	)

	if err := app.Start(); err != nil {
		logger.Error("failed to start service", "error", err)
		os.Exit(1)
	}

	logger.Info(
		"coraza ext_proc service started",
		"grpc_bind", app.GRPCAddr(),
		"metrics_bind", app.MetricsAddr(),
		"default_profile", cfg.DefaultProfile,
		"profiles", sortedProfileNames(runtimes),
		"profiles_path", cfg.ProfilesPath,
	)

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Wait(runCtx); err != nil {
		logger.Error("service exited with error", "error", err)
		os.Exit(1)
	}
}

func buildProfileRuntimes(cfg config.Config, logger *slog.Logger) (map[string]extproc.ProfileRuntime, error) {
	profiles := make(map[string]extproc.ProfileRuntime, len(cfg.Profiles))
	for name, profile := range cfg.Profiles {
		evaluator, err := waf.NewEvaluatorWithOptions(
			profile.RequestBodyLimit,
			profile.ResponseBodyLimit,
			waf.RuntimeOptions{
				ExcludedRuleIDs:          profile.ExcludedRuleIDs,
				InboundAnomalyThreshold:  profile.InboundAnomalyThreshold,
				OutboundAnomalyThreshold: profile.OutboundAnomalyThreshold,
				ResponseBodyMIMETypes:    profile.ResponseBodyMIMETypes,
				EarlyBlocking:            profile.EarlyBlocking,
			},
			logger,
		)
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}

		runtime, err := extproc.NewProfileRuntime(name, evaluator, profile.Mode, profile.OnError)
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		profiles[name] = runtime
	}
	return profiles, nil
}

func sortedProfileNames(profiles map[string]extproc.ProfileRuntime) []string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
