package waf

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

const defaultDirectives = `
Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecRuleEngine On
Include @owasp_crs/*.conf
`

const crsInitializationFile = "rules/@owasp_crs/REQUEST-901-INITIALIZATION.conf"

var (
	inboundThresholdDirectivePattern  = regexp.MustCompile(`(?i)setvar:\s*'tx\.inbound_anomaly_score_threshold=([0-9]+)'`)
	outboundThresholdDirectivePattern = regexp.MustCompile(`(?i)setvar:\s*'tx\.outbound_anomaly_score_threshold=([0-9]+)'`)
	totalScorePattern                 = regexp.MustCompile(`(?i)total score:\s*([0-9]+)`)
)

type RuntimeOptions struct {
	BlockingParanoiaLevel    *int
	DetectionParanoiaLevel   *int
	ExcludedRuleIDs          []int
	InboundAnomalyThreshold  *int
	OutboundAnomalyThreshold *int
	ResponseBodyMIMETypes    []string
	EarlyBlocking            bool
}

type Evaluator struct {
	waf               coraza.WAF
	logger            *slog.Logger
	inboundThreshold  model.ThresholdInfo
	outboundThreshold model.ThresholdInfo
}

type Session struct {
	tx                 corazatypes.Transaction
	req                model.Request
	logger             *slog.Logger
	requestBodyDone    bool
	responseBodyDone   bool
	responseHeaderDone bool
	closed             bool
}

func NewEvaluator(requestBodyLimit int, responseBodyLimit int, logger *slog.Logger) (*Evaluator, error) {
	return NewEvaluatorWithOptions(requestBodyLimit, responseBodyLimit, RuntimeOptions{}, logger)
}

func NewEvaluatorWithOptions(requestBodyLimit int, responseBodyLimit int, options RuntimeOptions, logger *slog.Logger) (*Evaluator, error) {
	if logger == nil {
		logger = slog.Default()
	}

	directives, inboundThreshold, outboundThreshold, err := buildRuntimeDirectives(options)
	if err != nil {
		return nil, err
	}
	if inboundThreshold.Source == model.ThresholdSourceUnknown {
		logger.Warn("unable to resolve inbound anomaly threshold from embedded CRS defaults")
	}
	if outboundThreshold.Source == model.ThresholdSourceUnknown {
		logger.Warn("unable to resolve outbound anomaly threshold from embedded CRS defaults")
	}

	return newEvaluatorWithDirectives(
		requestBodyLimit,
		responseBodyLimit,
		directives,
		inboundThreshold,
		outboundThreshold,
		logger,
	)
}

func NewEvaluatorWithDirectives(bodyLimit int, directives string, logger *slog.Logger) (*Evaluator, error) {
	return NewEvaluatorWithLimitsAndDirectives(bodyLimit, bodyLimit, directives, logger)
}

func NewEvaluatorWithLimitsAndDirectives(requestBodyLimit int, responseBodyLimit int, directives string, logger *slog.Logger) (*Evaluator, error) {
	unknownThreshold := model.ThresholdInfo{Source: model.ThresholdSourceUnknown}
	return newEvaluatorWithDirectives(
		requestBodyLimit,
		responseBodyLimit,
		directives,
		unknownThreshold,
		unknownThreshold,
		logger,
	)
}

func newEvaluatorWithDirectives(
	requestBodyLimit int,
	responseBodyLimit int,
	directives string,
	inboundThreshold model.ThresholdInfo,
	outboundThreshold model.ThresholdInfo,
	logger *slog.Logger,
) (*Evaluator, error) {
	if logger == nil {
		logger = slog.Default()
	}

	wafConfig := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithRequestBodyAccess().
		WithRequestBodyLimit(requestBodyLimit).
		WithRequestBodyInMemoryLimit(requestBodyLimit).
		WithResponseBodyAccess().
		WithResponseBodyLimit(responseBodyLimit).
		WithErrorCallback(func(mr corazatypes.MatchedRule) {
			logger.Warn("coraza error callback", "message", mr.ErrorLog())
		}).
		WithDirectives(strings.TrimSpace(directives))

	wafEngine, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, fmt.Errorf("init coraza waf: %w", err)
	}

	return &Evaluator{
		waf:               wafEngine,
		logger:            logger,
		inboundThreshold:  inboundThreshold,
		outboundThreshold: outboundThreshold,
	}, nil
}

func (e *Evaluator) ThresholdForAction(action model.ProcessingAction) model.ThresholdInfo {
	switch action {
	case model.ActionRequestHeaders, model.ActionRequestBody:
		return e.inboundThreshold
	case model.ActionResponseHeaders, model.ActionResponseBody:
		return e.outboundThreshold
	default:
		return model.ThresholdInfo{Source: model.ThresholdSourceUnknown}
	}
}

func (e *Evaluator) Evaluate(_ context.Context, req model.Request) model.Result {
	session := e.NewSession(req)
	defer session.Close()

	if result := session.ProcessRequestHeaders(); result.Decision != model.DecisionAllow {
		return result
	}
	if result := session.ProcessRequestBodyChunk(req.Body, true); result.Decision != model.DecisionAllow {
		return result
	}
	return model.Result{
		Decision:     model.DecisionAllow,
		Interruption: session.currentInterruption(),
	}
}

func (e *Evaluator) NewSession(req model.Request) *Session {
	if req.ID == "" {
		req.ID = strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.Path == "" {
		req.Path = "/"
	}
	if req.Protocol == "" {
		req.Protocol = "HTTP/1.1"
	}
	if req.Mode == "" {
		req.Mode = model.ModeDetect
	}

	tx := e.waf.NewTransactionWithID(req.ID)
	tx.ProcessConnection(req.ClientIP, req.ClientPort, req.ServerIP, req.ServerPort)
	tx.ProcessURI(req.Path, req.Method, req.Protocol)

	if req.Host != "" {
		tx.SetServerName(req.Host)
		tx.AddRequestHeader("host", req.Host)
	}
	for _, header := range req.Headers {
		tx.AddRequestHeader(strings.ToLower(header.Key), header.Value)
	}

	if req.Query != "" {
		queryValues, err := url.ParseQuery(req.Query)
		if err != nil {
			e.logger.Warn("unable to parse query arguments", "request_id", req.ID, "query", req.Query, "error", err)
		} else {
			for key, values := range queryValues {
				for _, value := range values {
					tx.AddGetRequestArgument(key, value)
				}
			}
		}
	}

	return &Session{
		tx:     tx,
		req:    req,
		logger: e.logger,
	}
}

func (s *Session) Request() model.Request {
	return s.req
}

func (s *Session) ProcessRequestHeaders() model.Result {
	if interruption := s.tx.ProcessRequestHeaders(); interruption != nil {
		return s.handleInterruption(interruption)
	}
	return model.Result{Decision: model.DecisionAllow}
}

func (s *Session) ProcessRequestBodyChunk(body []byte, endOfStream bool) model.Result {
	if s.requestBodyDone {
		return model.Result{Decision: model.DecisionAllow}
	}
	if len(body) > 0 {
		if interruption, _, err := s.tx.WriteRequestBody(body); err != nil {
			return internalError("write request body", err)
		} else if interruption != nil {
			return s.handleInterruption(interruption)
		}
	}
	if !endOfStream {
		return model.Result{Decision: model.DecisionAllow}
	}
	s.requestBodyDone = true
	if interruption, err := s.tx.ProcessRequestBody(); err != nil {
		return internalError("process request body", err)
	} else if interruption != nil {
		return s.handleInterruption(interruption)
	}
	return model.Result{Decision: model.DecisionAllow}
}

func (s *Session) ProcessResponseHeaders(statusCode int, protocol string, headers []model.Header) model.Result {
	if s.responseHeaderDone {
		return model.Result{Decision: model.DecisionAllow}
	}
	for _, header := range headers {
		s.tx.AddResponseHeader(strings.ToLower(header.Key), header.Value)
	}
	if protocol == "" {
		protocol = s.req.Protocol
	}
	if protocol == "" {
		protocol = "HTTP/1.1"
	}
	if interruption := s.tx.ProcessResponseHeaders(statusCode, protocol); interruption != nil {
		s.responseHeaderDone = true
		return s.handleInterruption(interruption)
	}
	s.responseHeaderDone = true
	return model.Result{Decision: model.DecisionAllow}
}

func (s *Session) ProcessResponseBodyChunk(body []byte, endOfStream bool) model.Result {
	if s.responseBodyDone {
		return model.Result{Decision: model.DecisionAllow}
	}
	if len(body) > 0 {
		if interruption, _, err := s.tx.WriteResponseBody(body); err != nil {
			return internalError("write response body", err)
		} else if interruption != nil {
			return s.handleInterruption(interruption)
		}
	}
	if !endOfStream {
		return model.Result{Decision: model.DecisionAllow}
	}
	s.responseBodyDone = true
	if interruption, err := s.tx.ProcessResponseBody(); err != nil {
		return internalError("process response body", err)
	} else if interruption != nil {
		return s.handleInterruption(interruption)
	}
	return model.Result{Decision: model.DecisionAllow}
}

func (s *Session) Close() {
	if s.closed {
		return
	}
	s.tx.ProcessLogging()
	_ = s.tx.Close()
	s.closed = true
}

func internalError(action string, err error) model.Result {
	return model.Result{
		Decision:       model.DecisionError,
		HTTPStatusCode: 500,
		Body:           "internal authorization error",
		Err:            fmt.Errorf("%s: %w", action, err),
	}
}

func (s *Session) currentInterruption() *model.Interruption {
	it := s.tx.Interruption()
	if it == nil {
		return nil
	}
	return &model.Interruption{
		RuleID: it.RuleID,
		Action: it.Action,
		Status: it.Status,
		Data:   it.Data,
	}
}

func (s *Session) handleInterruption(interruption *corazatypes.Interruption) model.Result {
	ruleID := strconv.Itoa(interruption.RuleID)
	anomalyScore := extractAnomalyScore(interruption, s.tx)
	s.logger.Warn(
		"coraza interruption",
		"request_id", s.req.ID,
		"mode", s.req.Mode,
		"rule_id", interruption.RuleID,
		"action", interruption.Action,
		"status", interruption.Status,
		"anomaly_score", anomalyScore,
		"host", s.req.Host,
		"path", s.req.Path,
	)

	if s.req.Mode == model.ModeBlock {
		return model.Result{
			Decision:       model.DecisionDeny,
			HTTPStatusCode: 403,
			Body:           "blocked by coraza waf",
			RuleID:         ruleID,
			Interruption: &model.Interruption{
				RuleID:       interruption.RuleID,
				Action:       interruption.Action,
				Status:       interruption.Status,
				Data:         interruption.Data,
				AnomalyScore: anomalyScore,
			},
		}
	}

	return model.Result{
		Decision: model.DecisionAllow,
		Interruption: &model.Interruption{
			RuleID:       interruption.RuleID,
			Action:       interruption.Action,
			Status:       interruption.Status,
			Data:         interruption.Data,
			AnomalyScore: anomalyScore,
		},
	}
}

func buildRuntimeDirectives(options RuntimeOptions) (string, model.ThresholdInfo, model.ThresholdInfo, error) {
	inboundThreshold, outboundThreshold, err := resolveThresholdMetadata(options)
	if err != nil {
		return "", model.ThresholdInfo{}, model.ThresholdInfo{}, err
	}

	lines := []string{
		"Include @coraza.conf-recommended",
		"Include @crs-setup.conf.example",
		"SecRuleEngine On",
		"SecResponseBodyLimitAction Reject",
	}

	if options.InboundAnomalyThreshold != nil {
		lines = append(
			lines,
			fmt.Sprintf(`SecAction "id:10000001,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=%d"`, *options.InboundAnomalyThreshold),
		)
	}
	if options.OutboundAnomalyThreshold != nil {
		lines = append(
			lines,
			fmt.Sprintf(`SecAction "id:10000002,phase:1,pass,nolog,setvar:tx.outbound_anomaly_score_threshold=%d"`, *options.OutboundAnomalyThreshold),
		)
	}
	if options.BlockingParanoiaLevel != nil {
		lines = append(
			lines,
			fmt.Sprintf(`SecAction "id:10000004,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d"`, *options.BlockingParanoiaLevel),
		)
	}
	if options.DetectionParanoiaLevel != nil {
		lines = append(
			lines,
			fmt.Sprintf(`SecAction "id:10000005,phase:1,pass,nolog,setvar:tx.detection_paranoia_level=%d"`, *options.DetectionParanoiaLevel),
		)
	}
	if options.EarlyBlocking {
		lines = append(
			lines,
			`SecAction "id:10000003,phase:1,pass,nolog,setvar:tx.early_blocking=1"`,
		)
	}

	lines = append(lines, "Include @owasp_crs/*.conf")

	for _, ruleID := range options.ExcludedRuleIDs {
		lines = append(lines, fmt.Sprintf("SecRuleRemoveById %d", ruleID))
	}
	if len(options.ResponseBodyMIMETypes) > 0 {
		lines = append(lines, "SecResponseBodyMimeType "+strings.Join(options.ResponseBodyMIMETypes, " "))
	}

	return strings.Join(lines, "\n"), inboundThreshold, outboundThreshold, nil
}

func resolveThresholdMetadata(options RuntimeOptions) (model.ThresholdInfo, model.ThresholdInfo, error) {
	if options.InboundAnomalyThreshold != nil && options.OutboundAnomalyThreshold != nil {
		return model.ThresholdInfo{
				Value:  cloneIntPointer(options.InboundAnomalyThreshold),
				Source: model.ThresholdSourceEnvOverride,
			}, model.ThresholdInfo{
				Value:  cloneIntPointer(options.OutboundAnomalyThreshold),
				Source: model.ThresholdSourceEnvOverride,
			}, nil
	}

	// When threshold env vars are unset, we do not inject SecAction overrides.
	// We derive defaults from embedded CRS initialization rules instead of using
	// hardcoded constants, so defaults follow upstream CRS changes.
	defaultInbound, defaultOutbound, err := resolveCRSDefaultThresholds()
	if err != nil {
		defaultInbound = nil
		defaultOutbound = nil
	}

	inbound := thresholdInfoFromOverrideOrDefault(options.InboundAnomalyThreshold, defaultInbound)
	outbound := thresholdInfoFromOverrideOrDefault(options.OutboundAnomalyThreshold, defaultOutbound)
	return inbound, outbound, nil
}

func thresholdInfoFromOverrideOrDefault(override *int, defaultValue *int) model.ThresholdInfo {
	if override != nil {
		return model.ThresholdInfo{
			Value:  cloneIntPointer(override),
			Source: model.ThresholdSourceEnvOverride,
		}
	}
	if defaultValue != nil {
		return model.ThresholdInfo{
			Value:  cloneIntPointer(defaultValue),
			Source: model.ThresholdSourceCRSDefault,
		}
	}
	return model.ThresholdInfo{Source: model.ThresholdSourceUnknown}
}

func resolveCRSDefaultThresholds() (*int, *int, error) {
	content, err := fs.ReadFile(coreruleset.FS, crsInitializationFile)
	if err != nil {
		return nil, nil, err
	}

	inbound := parseThresholdValue(content, inboundThresholdDirectivePattern)
	outbound := parseThresholdValue(content, outboundThresholdDirectivePattern)
	return inbound, outbound, nil
}

func parseThresholdValue(content []byte, pattern *regexp.Regexp) *int {
	match := pattern.FindSubmatch(content)
	if len(match) < 2 {
		return nil
	}
	value, err := strconv.Atoi(string(match[1]))
	if err != nil || value <= 0 {
		return nil
	}
	return &value
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func extractAnomalyScore(interruption *corazatypes.Interruption, tx corazatypes.Transaction) *int {
	if interruption == nil {
		return nil
	}

	candidates := []string{interruption.Data}
	matchedRules := tx.MatchedRules()
	for i := len(matchedRules) - 1; i >= 0; i-- {
		matched := matchedRules[i]
		if matched.Rule().ID() != interruption.RuleID {
			continue
		}
		candidates = append(candidates, matched.Message(), matched.Data())
		break
	}

	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" {
			continue
		}
		match := totalScorePattern.FindStringSubmatch(trimmed)
		if len(match) < 2 {
			continue
		}
		value, err := strconv.Atoi(match[1])
		if err != nil || value < 0 {
			continue
		}
		return &value
	}
	return nil
}
