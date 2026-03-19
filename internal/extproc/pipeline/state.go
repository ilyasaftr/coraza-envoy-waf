package pipeline

import (
	"strconv"
	"time"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/runtime"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

type ActionOutcome struct {
	Action          model.ProcessingAction
	Decision        model.Decision
	HTTPStatusCode  int
	Interrupted     bool
	RuleID          string
	Error           string
	FastPathReason  string
	AnomalyScore    *int
	Threshold       *int
	ThresholdSource model.ThresholdSource
}

type StreamState struct {
	request         model.Request
	profileName     string
	profile         runtime.ProfileRuntime
	session         runtime.Session
	requestBodyDone bool
	responseStarted bool
	finalResult     model.Result
	hasResult       bool
	streamClosed    bool
	outcomes        []ActionOutcome
}

func NewStreamState(defaultProfileName string, defaultProfile runtime.ProfileRuntime) *StreamState {
	return &StreamState{
		request: model.Request{
			ID:       strconv.FormatInt(time.Now().UnixNano(), 10),
			Method:   "GET",
			Path:     "/",
			Protocol: "HTTP/1.1",
		},
		profileName: defaultProfileName,
		profile:     defaultProfile,
	}
}

func (s *StreamState) SetProfile(name string, profile runtime.ProfileRuntime) {
	s.profileName = name
	s.profile = profile
}

func (s *StreamState) SetRequest(req model.Request) {
	s.request = req
}

func (s *StreamState) Request() model.Request {
	return s.request
}

func (s *StreamState) ProfileName() string {
	return s.profileName
}

func (s *StreamState) Outcomes() []ActionOutcome {
	return s.outcomes
}

func (s *StreamState) FinalResult() model.Result {
	return s.finalResult
}

func (s *StreamState) HasResult() bool {
	return s.hasResult
}

func (s *StreamState) Close() {
	if s.session != nil {
		s.session.Close()
	}
}

func (s *StreamState) EnsureFinalAllow() {
	if s.hasResult {
		return
	}
	s.finalResult = model.Result{Decision: model.DecisionAllow}
	s.hasResult = true
}

func (s *StreamState) CaptureResult(result model.Result) {
	if result.Decision == "" {
		return
	}
	if result.Decision == model.DecisionDeny {
		s.finalResult = result
		s.hasResult = true
		return
	}
	if result.Decision == model.DecisionError {
		s.finalResult = result
		s.hasResult = true
		return
	}
	if result.Interruption != nil {
		if !s.hasResult || s.finalResult.Decision == model.DecisionAllow {
			s.finalResult = result
			s.hasResult = true
		}
		return
	}
	if result.Err != nil {
		if !s.hasResult || s.finalResult.Decision == model.DecisionAllow {
			s.finalResult = result
			s.hasResult = true
		}
		return
	}
	if !s.hasResult || s.finalResult.Decision == "" {
		s.finalResult = model.Result{Decision: model.DecisionAllow}
		s.hasResult = true
	}
}

func (s *StreamState) SetError(err error) {
	s.finalResult = model.Result{
		Decision:       model.DecisionError,
		HTTPStatusCode: 503,
		Body:           "internal authorization error",
		Err:            err,
	}
	s.hasResult = true
}

func (s *StreamState) MarkStreamClosed() {
	s.streamClosed = true
}

func (s *StreamState) StreamClosed() bool {
	return s.streamClosed
}

func (s *StreamState) RequestComplete() bool {
	return s.requestBodyDone
}

func (s *StreamState) ProcessRequestHeaders() model.Result {
	s.ensureSession()
	return s.session.ProcessRequestHeaders()
}

func (s *StreamState) ProcessRequestBody(body []byte, endOfStream bool) model.Result {
	if s.requestBodyDone {
		return model.Result{Decision: model.DecisionAllow}
	}
	s.ensureSession()
	result := s.session.ProcessRequestBodyChunk(body, endOfStream)
	if endOfStream {
		s.requestBodyDone = true
	}
	return result
}

func (s *StreamState) EnsureRequestBodyFinalized() (model.Result, bool) {
	if s.requestBodyDone {
		return model.Result{Decision: model.DecisionAllow}, false
	}
	return s.ProcessRequestBody(nil, true), true
}

func (s *StreamState) MarkRequestBodyFastPath(reason string) {
	if s.requestBodyDone {
		return
	}
	s.requestBodyDone = true
	threshold := s.profile.ThresholdForAction(model.ActionRequestBody)

	outcome := ActionOutcome{
		Action:          model.ActionRequestBody,
		Decision:        model.DecisionAllow,
		FastPathReason:  reason,
		ThresholdSource: threshold.Source,
	}
	if threshold.Value != nil {
		value := *threshold.Value
		outcome.Threshold = &value
	}

	s.outcomes = append(s.outcomes, outcome)
}

func (s *StreamState) ProcessResponseHeaders(statusCode int, protocol string, headers []model.Header) model.Result {
	s.ensureSession()
	s.responseStarted = true
	return s.session.ProcessResponseHeaders(statusCode, protocol, headers)
}

func (s *StreamState) ProcessResponseBody(body []byte, endOfStream bool) model.Result {
	s.ensureSession()
	s.responseStarted = true
	return s.session.ProcessResponseBodyChunk(body, endOfStream)
}

func (s *StreamState) FinalizeAction(action model.ProcessingAction, rawResult model.Result) model.Result {
	resolvedResult := rawResult
	if rawResult.Decision == model.DecisionError && shouldFailOpenAction(action) {
		resolvedResult.Decision = model.DecisionAllow
		resolvedResult.HTTPStatusCode = 0
		resolvedResult.Body = ""
	}

	threshold := s.profile.ThresholdForAction(action)
	s.outcomes = append(s.outcomes, buildActionOutcome(action, rawResult, resolvedResult, threshold))
	return resolvedResult
}

func (s *StreamState) ensureSession() {
	if s.session != nil {
		return
	}
	s.session = s.profile.NewSession(s.request)
}

func buildActionOutcome(
	action model.ProcessingAction,
	rawResult model.Result,
	resolvedResult model.Result,
	threshold model.ThresholdInfo,
) ActionOutcome {
	var ruleID string
	if rawResult.RuleID != "" {
		ruleID = rawResult.RuleID
	} else if rawResult.Interruption != nil {
		ruleID = strconv.Itoa(rawResult.Interruption.RuleID)
	}

	outcome := ActionOutcome{
		Action:          action,
		Decision:        resolvedResult.Decision,
		HTTPStatusCode:  resolvedResult.HTTPStatusCode,
		Interrupted:     rawResult.Interruption != nil,
		RuleID:          ruleID,
		ThresholdSource: threshold.Source,
	}

	if rawResult.Err != nil {
		outcome.Error = rawResult.Err.Error()
	}
	if rawResult.Interruption != nil {
		outcome.AnomalyScore = rawResult.Interruption.AnomalyScore
	}
	if threshold.Value != nil {
		value := *threshold.Value
		outcome.Threshold = &value
	}

	return outcome
}

func shouldFailOpenAction(action model.ProcessingAction) bool {
	switch action {
	case model.ActionRequestHeaders, model.ActionRequestBody, model.ActionResponseHeaders, model.ActionResponseBody:
		return true
	default:
		return false
	}
}
