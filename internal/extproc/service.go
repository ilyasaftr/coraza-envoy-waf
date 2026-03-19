package extproc

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/observe"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/pipeline"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/profilemeta"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/protoio"
	extprocruntime "github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/runtime"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/waf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Session = extprocruntime.Session
type ProfileRuntime = extprocruntime.ProfileRuntime
type streamState = pipeline.StreamState

const requestBodyFastPathReason = "bodyless_safe_method"

type requestBodyFastPathMode string

const (
	requestBodyFastPathModeStrict requestBodyFastPathMode = "strict"
	requestBodyFastPathModeOff    requestBodyFastPathMode = "off"
)

type Service struct {
	extprocv3.UnimplementedExternalProcessorServer
	profiles       map[string]ProfileRuntime
	defaultProfile string
	resolver       *profilemeta.Resolver
	recorder       model.Recorder
	logger         *slog.Logger
	fastPathMode   requestBodyFastPathMode
}

func NewProfileRuntime(name string, evaluator *waf.Evaluator) (ProfileRuntime, error) {
	return extprocruntime.NewProfileRuntime(name, evaluator)
}

func NewService(
	profiles map[string]ProfileRuntime,
	defaultProfile string,
	fastPathMode string,
	recorder model.Recorder,
	logger *slog.Logger,
) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if recorder == nil {
		recorder = noopRecorder{}
	}
	normalizedFastPathMode, err := normalizeRequestBodyFastPathMode(fastPathMode)
	if err != nil {
		return nil, err
	}

	normalizedProfiles, normalizedDefault, err := extprocruntime.NormalizeProfiles(profiles, defaultProfile)
	if err != nil {
		return nil, err
	}

	return &Service{
		profiles:       normalizedProfiles,
		defaultProfile: normalizedDefault,
		resolver:       profilemeta.NewResolver(normalizedProfiles, normalizedDefault, logger),
		recorder:       recorder,
		logger:         logger,
		fastPathMode:   normalizedFastPathMode,
	}, nil
}

func (s *Service) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	defaultProfile := s.profiles[s.defaultProfile]
	state := pipeline.NewStreamState(s.defaultProfile, defaultProfile)

	defer func() {
		state.Close()
		state.EnsureFinalAllow()
		s.recorder.Record(state.Request(), state.ProfileName(), state.FinalResult())
		observe.LogFinalResult(s.logger, state.Request(), state.ProfileName(), state.FinalResult(), state.Outcomes())
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if shouldIgnoreRecvError(err, state) {
				return nil
			}
			state.SetError(fmt.Errorf("read processing request: %w", err))
			return err
		}

		result, response := s.handleMessage(state, msg)
		state.CaptureResult(result)

		if msg.GetObservabilityMode() {
			continue
		}

		if response != nil {
			if err := stream.Send(response); err != nil {
				state.SetError(fmt.Errorf("send processing response: %w", err))
				return err
			}
			if response.GetImmediateResponse() != nil || response.GetStreamedImmediateResponse() != nil {
				state.MarkStreamClosed()
				return nil
			}
		}
	}
}

func (s *Service) handleMessage(state *streamState, msg *extprocv3.ProcessingRequest) (model.Result, *extprocv3.ProcessingResponse) {
	switch req := msg.GetRequest().(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		profilemeta.LogRequestAttributes(s.logger, msg)

		profileName, profile := s.resolver.Resolve(msg)
		state.SetProfile(profileName, profile)

		parsed := protoio.ParseRequestHeaders(req.RequestHeaders)
		state.SetRequest(parsed)

		result := state.ProcessRequestHeaders()
		resolved := state.FinalizeAction(model.ActionRequestHeaders, result)
		if resolved.Decision == model.DecisionDeny || resolved.Decision == model.DecisionError {
			return resolved, protoio.ResponseForAction(model.ActionRequestHeaders, resolved)
		}

		// Envoy can send request headers with end_of_stream=true for bodyless requests.
		// We still need to run request-body finalization so phase-2 logic executes.
		if req.RequestHeaders.GetEndOfStream() {
			if shouldUseRequestBodyFastPath(state.Request(), s.fastPathMode) {
				state.MarkRequestBodyFastPath(requestBodyFastPathReason)
				return resolved, protoio.ResponseForAction(model.ActionRequestHeaders, resolved)
			}
			bodyResult, _ := state.EnsureRequestBodyFinalized()
			bodyResolved := state.FinalizeAction(model.ActionRequestBody, bodyResult)
			return bodyResolved, protoio.ResponseForAction(model.ActionRequestHeaders, bodyResolved)
		}

		return resolved, protoio.ResponseForAction(model.ActionRequestHeaders, resolved)

	case *extprocv3.ProcessingRequest_RequestBody:
		result := state.ProcessRequestBody(req.RequestBody.GetBody(), req.RequestBody.GetEndOfStream())
		resolved := state.FinalizeAction(model.ActionRequestBody, result)
		return resolved, protoio.ResponseForAction(model.ActionRequestBody, resolved)

	case *extprocv3.ProcessingRequest_ResponseHeaders:
		if bodyResult, finalized := state.EnsureRequestBodyFinalized(); finalized {
			bodyResolved := state.FinalizeAction(model.ActionRequestBody, bodyResult)
			if bodyResolved.Decision == model.DecisionDeny || bodyResolved.Decision == model.DecisionError {
				return bodyResolved, protoio.ResponseForAction(model.ActionResponseHeaders, bodyResolved)
			}
		}

		statusCode, protocol, headers := protoio.ParseResponseHeaders(req.ResponseHeaders)
		result := state.ProcessResponseHeaders(statusCode, protocol, headers)
		resolved := state.FinalizeAction(model.ActionResponseHeaders, result)
		if req.ResponseHeaders.GetEndOfStream() {
			state.MarkStreamClosed()
		}
		return resolved, protoio.ResponseForAction(model.ActionResponseHeaders, resolved)

	case *extprocv3.ProcessingRequest_ResponseBody:
		result := state.ProcessResponseBody(req.ResponseBody.GetBody(), req.ResponseBody.GetEndOfStream())
		resolved := state.FinalizeAction(model.ActionResponseBody, result)
		if req.ResponseBody.GetEndOfStream() {
			state.MarkStreamClosed()
		}
		return resolved, protoio.ResponseForAction(model.ActionResponseBody, resolved)

	case *extprocv3.ProcessingRequest_RequestTrailers:
		allowed := model.Result{Decision: model.DecisionAllow}
		return allowed, protoio.ContinueTrailersResponse(true)

	case *extprocv3.ProcessingRequest_ResponseTrailers:
		allowed := model.Result{Decision: model.DecisionAllow}
		return allowed, protoio.ContinueTrailersResponse(false)

	default:
		errResult := model.Result{
			Decision:       model.DecisionError,
			HTTPStatusCode: 503,
			Body:           "internal authorization error",
			Err:            errors.New("unsupported ext_proc request type"),
		}
		resolved := state.FinalizeAction(model.ActionUnknown, errResult)
		return resolved, protoio.ResponseForAction(model.ActionUnknown, resolved)
	}
}

type noopRecorder struct{}

func (noopRecorder) Record(model.Request, string, model.Result) {}

func shouldIgnoreRecvError(err error, state *streamState) bool {
	if err == nil || state == nil {
		return false
	}
	if status.Code(err) != codes.Canceled {
		return false
	}
	if state.StreamClosed() {
		return true
	}
	if !state.RequestComplete() {
		return false
	}
	return state.FinalResult().Decision != model.DecisionError
}

func shouldUseRequestBodyFastPath(req model.Request, mode requestBodyFastPathMode) bool {
	if mode != requestBodyFastPathModeStrict {
		return false
	}

	if !isBodylessSafeMethod(req.Method) {
		return false
	}

	if strings.TrimSpace(req.Query) != "" {
		return false
	}

	contentLengthZero := true
	for _, header := range req.Headers {
		key := strings.TrimSpace(strings.ToLower(header.Key))
		value := strings.TrimSpace(header.Value)
		switch key {
		case "content-length":
			if value != "" && value != "0" {
				contentLengthZero = false
			}
		case "transfer-encoding":
			if value != "" {
				contentLengthZero = false
			}
		}
	}

	return contentLengthZero
}

func isBodylessSafeMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

func normalizeRequestBodyFastPathMode(raw string) (requestBodyFastPathMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(requestBodyFastPathModeStrict):
		return requestBodyFastPathModeStrict, nil
	case string(requestBodyFastPathModeOff):
		return requestBodyFastPathModeOff, nil
	default:
		return requestBodyFastPathModeStrict, nil
	}
}
