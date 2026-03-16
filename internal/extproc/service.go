package extproc

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

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

type Service struct {
	extprocv3.UnimplementedExternalProcessorServer
	profiles       map[string]ProfileRuntime
	defaultProfile string
	resolver       *profilemeta.Resolver
	recorder       model.Recorder
	logger         *slog.Logger
}

func NewProfileRuntime(name string, evaluator *waf.Evaluator, mode model.Mode, onError model.OnErrorPolicy) (ProfileRuntime, error) {
	return extprocruntime.NewProfileRuntime(name, evaluator, mode, onError)
}

func NewService(profiles map[string]ProfileRuntime, defaultProfile string, recorder model.Recorder, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if recorder == nil {
		recorder = noopRecorder{}
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
	}, nil
}

func (s *Service) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	defaultProfile := s.profiles[s.defaultProfile]
	state := pipeline.NewStreamState(s.defaultProfile, defaultProfile)

	defer func() {
		state.Close()
		state.EnsureFinalAllow()
		s.recorder.Record(state.Request(), state.FinalResult())
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

		parsed := protoio.ParseRequestHeaders(req.RequestHeaders, profile.Mode)
		state.SetRequest(parsed)

		result := state.ProcessRequestHeaders()
		resolved := state.FinalizeAction(model.ActionRequestHeaders, result)
		if resolved.Decision == model.DecisionDeny || resolved.Decision == model.DecisionError {
			return resolved, protoio.ResponseForAction(model.ActionRequestHeaders, state.Request().Mode, resolved)
		}

		// Envoy can send request headers with end_of_stream=true for bodyless requests.
		// We still need to run request-body finalization so phase-2 logic executes.
		if req.RequestHeaders.GetEndOfStream() {
			bodyResult, _ := state.EnsureRequestBodyFinalized()
			bodyResolved := state.FinalizeAction(model.ActionRequestBody, bodyResult)
			return bodyResolved, protoio.ResponseForAction(model.ActionRequestHeaders, state.Request().Mode, bodyResolved)
		}

		return resolved, protoio.ResponseForAction(model.ActionRequestHeaders, state.Request().Mode, resolved)

	case *extprocv3.ProcessingRequest_RequestBody:
		result := state.ProcessRequestBody(req.RequestBody.GetBody(), req.RequestBody.GetEndOfStream())
		resolved := state.FinalizeAction(model.ActionRequestBody, result)
		return resolved, protoio.ResponseForAction(model.ActionRequestBody, state.Request().Mode, resolved)

	case *extprocv3.ProcessingRequest_ResponseHeaders:
		if bodyResult, finalized := state.EnsureRequestBodyFinalized(); finalized {
			bodyResolved := state.FinalizeAction(model.ActionRequestBody, bodyResult)
			if bodyResolved.Decision == model.DecisionDeny || bodyResolved.Decision == model.DecisionError {
				return bodyResolved, protoio.ResponseForAction(model.ActionResponseHeaders, state.Request().Mode, bodyResolved)
			}
		}

		statusCode, protocol, headers := protoio.ParseResponseHeaders(req.ResponseHeaders)
		result := state.ProcessResponseHeaders(statusCode, protocol, headers)
		resolved := state.FinalizeAction(model.ActionResponseHeaders, result)
		if req.ResponseHeaders.GetEndOfStream() {
			state.MarkStreamClosed()
		}
		return resolved, protoio.ResponseForAction(model.ActionResponseHeaders, state.Request().Mode, resolved)

	case *extprocv3.ProcessingRequest_ResponseBody:
		result := state.ProcessResponseBody(req.ResponseBody.GetBody(), req.ResponseBody.GetEndOfStream())
		resolved := state.FinalizeAction(model.ActionResponseBody, result)
		if req.ResponseBody.GetEndOfStream() {
			state.MarkStreamClosed()
		}
		return resolved, protoio.ResponseForAction(model.ActionResponseBody, state.Request().Mode, resolved)

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
		return resolved, protoio.ResponseForAction(model.ActionUnknown, state.Request().Mode, resolved)
	}
}

type noopRecorder struct{}

func (noopRecorder) Record(model.Request, model.Result) {}

func shouldIgnoreRecvError(err error, state *streamState) bool {
	if err == nil || state == nil {
		return false
	}
	if status.Code(err) != codes.Canceled {
		return false
	}
	return state.StreamClosed()
}
