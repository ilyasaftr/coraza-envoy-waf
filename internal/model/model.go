package model

import "context"

type ProcessingAction string

const (
	ActionUnknown         ProcessingAction = "unknown"
	ActionRequestHeaders  ProcessingAction = "request_headers"
	ActionRequestBody     ProcessingAction = "request_body"
	ActionResponseHeaders ProcessingAction = "response_headers"
	ActionResponseBody    ProcessingAction = "response_body"
)

type ThresholdSource string

const (
	ThresholdSourceProfileDirective ThresholdSource = "profile_directive"
	ThresholdSourceCRSDefault       ThresholdSource = "crs_default"
	ThresholdSourceUnknown          ThresholdSource = "unknown"
)

type ThresholdInfo struct {
	Value  *int
	Source ThresholdSource
}

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionError Decision = "error"
)

type Header struct {
	Key   string
	Value string
}

type Request struct {
	ID       string
	Method   string
	Path     string
	Query    string
	Host     string
	Protocol string

	Headers []Header
	Body    []byte

	ClientIP   string
	ClientPort int
	ServerIP   string
	ServerPort int
}

type Interruption struct {
	RuleID       int
	Action       string
	Status       int
	Data         string
	AnomalyScore *int
}

type Result struct {
	Decision       Decision
	HTTPStatusCode int
	Body           string
	RuleID         string
	Interruption   *Interruption
	Err            error
}

type Evaluator interface {
	Evaluate(ctx context.Context, req Request) Result
}

type Recorder interface {
	Record(req Request, result Result)
}
