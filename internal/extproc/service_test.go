package extproc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/pipeline"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/waf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

const blockTestDirectives = `
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/html
SecRule REQUEST_URI "@streq /blocked" "id:101,phase:1,deny,status:403"
SecRule RESPONSE_BODY "@contains blocked-response" "id:202,phase:4,deny,status:403"
`

const detectTestDirectives = `
SecRuleEngine DetectionOnly
SecResponseBodyAccess On
SecResponseBodyMimeType text/html
SecRule REQUEST_URI "@streq /blocked" "id:101,phase:1,deny,status:403"
SecRule RESPONSE_BODY "@contains blocked-response" "id:202,phase:4,deny,status:403"
`

func TestHandleMessageBlocksOnRequestHeaders(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"strict": newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "strict")

	state := service.newStreamState()
	result, resp := service.handleMessage(state, requestHeadersMessage("/blocked", nil))
	if result.Decision != model.DecisionDeny {
		t.Fatalf("expected deny decision, got %q", result.Decision)
	}
	if resp.GetImmediateResponse() == nil {
		t.Fatal("expected immediate response")
	}
}

func TestImmediateDenyHeadersUseWAFPrefix(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"strict": newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "strict")

	state := service.newStreamState()
	result, resp := service.handleMessage(state, requestHeadersMessage("/blocked", nil))
	if result.Decision != model.DecisionDeny {
		t.Fatalf("expected deny decision, got %q", result.Decision)
	}

	immediate := resp.GetImmediateResponse()
	if immediate == nil {
		t.Fatal("expected immediate deny response")
	}

	headers := map[string]string{}
	for _, option := range immediate.GetHeaders().GetSetHeaders() {
		headers[option.GetHeader().GetKey()] = string(option.GetHeader().GetRawValue())
	}

	if got := headers["x-waf-rule-id"]; got == "" {
		t.Fatal("expected x-waf-rule-id to be set")
	}
}

func TestHandleMessageBlocksOnResponseBody(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"strict": newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "strict")

	state := service.newStreamState()

	_, resp := service.handleMessage(state, requestHeadersMessage("/ok", nil))
	if resp.GetImmediateResponse() != nil {
		t.Fatal("unexpected immediate response during request headers")
	}

	_, resp = service.handleMessage(state, &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(
					":status", "200",
					"content-type", "text/html",
				),
			},
		},
	})
	if resp.GetImmediateResponse() != nil {
		t.Fatal("unexpected immediate response during response headers")
	}

	result, resp := service.handleMessage(state, &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        []byte("blocked-response"),
				EndOfStream: true,
			},
		},
	})
	if result.Decision != model.DecisionDeny {
		t.Fatalf("expected deny decision, got %q", result.Decision)
	}
	if resp.GetImmediateResponse() == nil {
		t.Fatal("expected immediate response on blocked response body")
	}
}

func TestHandleMessageAllowsBenignTraffic(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"strict": newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "strict")

	state := service.newStreamState()
	result, resp := service.handleMessage(state, requestHeadersMessage("/ok", nil))
	if result.Decision != model.DecisionAllow {
		t.Fatalf("expected allow decision, got %q", result.Decision)
	}
	if resp.GetRequestHeaders() == nil {
		t.Fatal("expected request headers continue response")
	}
}

func TestRequestHeadersEndOfStreamTriggersRequestBodyPhase(t *testing.T) {
	stub := &stubSession{
		requestHeadersResult: model.Result{Decision: model.DecisionAllow},
		requestBodyResult: model.Result{
			Decision:       model.DecisionDeny,
			HTTPStatusCode: 403,
			RuleID:         "949110",
		},
	}
	service := newStubService(t, map[string]ProfileRuntime{
		"strict": newStubRuntime("strict", stub, model.ThresholdInfo{}, model.ThresholdInfo{}),
	}, "strict")

	state := service.newStreamState()
	result, resp := service.handleMessage(state, requestHeadersMessageWithEndOfStream("/ok", nil, true))
	if result.Decision != model.DecisionDeny {
		t.Fatalf("expected deny decision, got %q", result.Decision)
	}
	if resp.GetImmediateResponse() == nil {
		t.Fatal("expected immediate deny response")
	}
	if stub.requestBodyCalls != 1 {
		t.Fatalf("expected request body to be processed once, got %d", stub.requestBodyCalls)
	}
	outcomes := state.Outcomes()
	if len(outcomes) < 2 || outcomes[1].Action != model.ActionRequestBody {
		t.Fatalf("expected request_body outcome, got %+v", outcomes)
	}
}

func TestResponseHeadersFinalizeRequestBodyWhenMissingRequestBodyMessage(t *testing.T) {
	stub := &stubSession{
		requestHeadersResult: model.Result{Decision: model.DecisionAllow},
		requestBodyResult: model.Result{
			Decision:       model.DecisionDeny,
			HTTPStatusCode: 403,
			RuleID:         "949110",
		},
		responseHeadersResult: model.Result{Decision: model.DecisionAllow},
	}
	service := newStubService(t, map[string]ProfileRuntime{
		"strict": newStubRuntime("strict", stub, model.ThresholdInfo{}, model.ThresholdInfo{}),
	}, "strict")

	state := service.newStreamState()
	_, _ = service.handleMessage(state, requestHeadersMessageWithEndOfStream("/ok", nil, false))

	result, resp := service.handleMessage(state, &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: headerMap(
					":status", "200",
					"content-type", "application/json",
				),
			},
		},
	})

	if result.Decision != model.DecisionDeny {
		t.Fatalf("expected deny decision, got %q", result.Decision)
	}
	if resp.GetImmediateResponse() == nil {
		t.Fatal("expected immediate deny response")
	}
	if stub.requestBodyCalls != 1 {
		t.Fatalf("expected request body to be finalized once, got %d", stub.requestBodyCalls)
	}
	if stub.responseHeadersCalls != 0 {
		t.Fatalf("expected response headers processing to be skipped on request body deny, got %d calls", stub.responseHeadersCalls)
	}
}

func TestProcessIgnoresCanceledAfterSuccessfulResult(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"strict": newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "strict")
	recorder := &capturingRecorder{}
	service.recorder = recorder

	stream := &stubProcessStream{
		recvMessages: []*extprocv3.ProcessingRequest{
			requestHeadersMessageWithEndOfStream("/ok", nil, false),
			{
				Request: &extprocv3.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &extprocv3.HttpHeaders{
						Headers: headerMap(
							":status", "200",
							"content-type", "application/json",
						),
					},
				},
			},
			{
				Request: &extprocv3.ProcessingRequest_ResponseBody{
					ResponseBody: &extprocv3.HttpBody{
						Body:        []byte(`{"ok":true}`),
						EndOfStream: true,
					},
				},
			},
		},
		recvErr: status.Error(codes.Canceled, "context canceled"),
	}

	err := service.Process(stream)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if recorder.result.Decision == model.DecisionError {
		t.Fatalf("expected no final error override, got %+v", recorder.result)
	}
	if len(stream.sent) == 0 {
		t.Fatal("expected at least one processing response to be sent")
	}
	if !stream.responseBodyEosSeen {
		t.Fatal("expected response body end_of_stream to be processed before cancel")
	}
}

func TestProcessIgnoresCanceledAfterSuccessfulRequestOnlyResult(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"strict": newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "strict")
	recorder := &capturingRecorder{}
	service.recorder = recorder

	stream := &stubProcessStream{
		recvMessages: []*extprocv3.ProcessingRequest{
			requestHeadersMessageWithEndOfStream("/ok", nil, true),
		},
		recvErr: status.Error(codes.Canceled, "context canceled"),
	}

	err := service.Process(stream)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if recorder.result.Decision == model.DecisionError {
		t.Fatalf("expected no final error override, got %+v", recorder.result)
	}
}

func TestProcessIgnoresCanceledAfterSuccessfulResponseHeadersOnlyResult(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"strict": newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "strict")
	recorder := &capturingRecorder{}
	service.recorder = recorder

	stream := &stubProcessStream{
		recvMessages: []*extprocv3.ProcessingRequest{
			requestHeadersMessageWithEndOfStream("/ok", nil, false),
			{
				Request: &extprocv3.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &extprocv3.HttpHeaders{
						Headers: headerMap(
							":status", "200",
							"content-type", "application/json",
						),
						EndOfStream: true,
					},
				},
			},
		},
		recvErr: status.Error(codes.Canceled, "context canceled"),
	}

	err := service.Process(stream)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if recorder.result.Decision == model.DecisionError {
		t.Fatalf("expected no final error override, got %+v", recorder.result)
	}
}

func TestProcessReturnsErrorOnEarlyCanceledStream(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"strict": newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "strict")

	stream := &stubProcessStream{
		recvErr: status.Error(codes.Canceled, "context canceled"),
	}

	err := service.Process(stream)
	if err == nil {
		t.Fatal("expected early canceled stream to return error")
	}
}

func TestHandleMessageUnknownTypeReturnsInternalError(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"strict": newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "strict")

	state := service.newStreamState()
	result, resp := service.handleMessage(state, &extprocv3.ProcessingRequest{})
	if result.Decision != model.DecisionError {
		t.Fatalf("expected error decision, got %q", result.Decision)
	}
	if result.HTTPStatusCode != 503 {
		t.Fatalf("expected status 503, got %d", result.HTTPStatusCode)
	}
	if resp.GetImmediateResponse() == nil {
		t.Fatal("expected immediate response for unsupported request type")
	}
	if got := resp.GetImmediateResponse().GetStatus().GetCode(); got != typev3.StatusCode_ServiceUnavailable {
		t.Fatalf("expected service unavailable, got %s", got.String())
	}
}

func TestSelectProfileFromRouteMetadataShortKey(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"default": newEvaluatorRuntime(t, "default", detectTestDirectives),
		"strict":  newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "default")

	state := service.newStreamState()
	msg := requestHeadersMessage("/blocked", routeMetadataAttributes("coraza-profile", "strict"))

	result, _ := service.handleMessage(state, msg)
	if state.ProfileName() != "strict" {
		t.Fatalf("expected strict profile, got %q", state.ProfileName())
	}
	if result.Decision != model.DecisionDeny {
		t.Fatalf("expected block profile to deny request, got %q", result.Decision)
	}
}

func TestSelectProfileFromRouteMetadataFullKey(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"default": newEvaluatorRuntime(t, "default", detectTestDirectives),
		"strict":  newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "default")

	state := service.newStreamState()
	msg := requestHeadersMessage("/blocked", routeMetadataAttributes("gateway.envoyproxy.io/coraza-profile", "strict"))

	result, _ := service.handleMessage(state, msg)
	if state.ProfileName() != "strict" {
		t.Fatalf("expected strict profile, got %q", state.ProfileName())
	}
	if result.Decision != model.DecisionDeny {
		t.Fatalf("expected deny decision, got %q", result.Decision)
	}
}

func TestSelectProfileFromNamespacedExtProcAttributes(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"default": newEvaluatorRuntime(t, "default", detectTestDirectives),
		"strict":  newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "default")

	state := service.newStreamState()
	msg := requestHeadersMessage("/blocked", routeMetadataUnderExtProcNamespaceAttributes("coraza-profile", "strict"))

	result, _ := service.handleMessage(state, msg)
	if state.ProfileName() != "strict" {
		t.Fatalf("expected strict profile, got %q", state.ProfileName())
	}
	if result.Decision != model.DecisionDeny {
		t.Fatalf("expected deny decision, got %q", result.Decision)
	}
}

func TestSelectProfileFromNamespacedExtProcAttributesTextMetadata(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"default": newEvaluatorRuntime(t, "default", detectTestDirectives),
		"strict":  newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "default")

	state := service.newStreamState()
	msg := requestHeadersMessage("/blocked", routeMetadataTextUnderExtProcNamespaceAttributes("coraza-profile", "strict"))

	result, _ := service.handleMessage(state, msg)
	if state.ProfileName() != "strict" {
		t.Fatalf("expected strict profile, got %q", state.ProfileName())
	}
	if result.Decision != model.DecisionDeny {
		t.Fatalf("expected deny decision, got %q", result.Decision)
	}
}

func TestUnknownProfileFallsBackToDefault(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"default": newEvaluatorRuntime(t, "default", detectTestDirectives),
		"strict":  newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "default")

	state := service.newStreamState()
	msg := requestHeadersMessage("/blocked", routeMetadataAttributes("coraza-profile", "missing"))

	result, resp := service.handleMessage(state, msg)
	if state.ProfileName() != "default" {
		t.Fatalf("expected fallback default profile, got %q", state.ProfileName())
	}
	if result.Decision != model.DecisionAllow {
		t.Fatalf("expected detection-only fallback to allow request, got %q", result.Decision)
	}
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected continue response in detection-only mode")
	}
}

func TestSelectProfileFromMetadataContext(t *testing.T) {
	service := newEvaluatorService(t, map[string]ProfileRuntime{
		"default": newEvaluatorRuntime(t, "default", detectTestDirectives),
		"strict":  newEvaluatorRuntime(t, "strict", blockTestDirectives),
	}, "default")

	state := service.newStreamState()
	msg := requestHeadersMessage("/blocked", nil)
	msg.MetadataContext = &corev3.Metadata{
		FilterMetadata: map[string]*structpb.Struct{
			"envoy-gateway": mustStruct(map[string]any{
				"resources": []any{
					map[string]any{
						"annotations": map[string]any{
							"coraza-profile": "strict",
						},
					},
				},
			}),
		},
	}

	result, _ := service.handleMessage(state, msg)
	if state.ProfileName() != "strict" {
		t.Fatalf("expected strict profile, got %q", state.ProfileName())
	}
	if result.Decision != model.DecisionDeny {
		t.Fatalf("expected deny decision, got %q", result.Decision)
	}
}

func TestInternalActionErrorsFailOpen(t *testing.T) {
	t.Run("request headers", func(t *testing.T) {
		stub := &stubSession{
			requestHeadersResult: model.Result{
				Decision: model.DecisionError,
				Err:      errors.New("synthetic request headers failure"),
			},
		}
		service := newStubService(t, map[string]ProfileRuntime{
			"strict": newStubRuntime("strict", stub, model.ThresholdInfo{}, model.ThresholdInfo{}),
		}, "strict")

		state := service.newStreamState()
		result, resp := service.handleMessage(state, requestHeadersMessage("/ok", nil))
		if result.Decision != model.DecisionAllow {
			t.Fatalf("expected allow decision, got %q", result.Decision)
		}
		if resp.GetRequestHeaders() == nil {
			t.Fatal("expected continue request headers response")
		}
		if got := state.Outcomes()[0].Error; got == "" {
			t.Fatal("expected error recorded in action outcome")
		}
	})

	t.Run("request body", func(t *testing.T) {
		stub := &stubSession{
			requestHeadersResult: model.Result{Decision: model.DecisionAllow},
			requestBodyResult: model.Result{
				Decision: model.DecisionError,
				Err:      errors.New("synthetic request body failure"),
			},
		}
		service := newStubService(t, map[string]ProfileRuntime{
			"strict": newStubRuntime("strict", stub, model.ThresholdInfo{}, model.ThresholdInfo{}),
		}, "strict")

		state := service.newStreamState()
		_, _ = service.handleMessage(state, requestHeadersMessage("/ok", nil))
		result, resp := service.handleMessage(state, &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_RequestBody{
				RequestBody: &extprocv3.HttpBody{
					Body:        []byte("payload"),
					EndOfStream: true,
				},
			},
		})
		if result.Decision != model.DecisionAllow {
			t.Fatalf("expected allow decision, got %q", result.Decision)
		}
		if resp.GetRequestBody() == nil {
			t.Fatal("expected continue request body response")
		}
	})

	t.Run("response headers", func(t *testing.T) {
		stub := &stubSession{
			requestHeadersResult: model.Result{Decision: model.DecisionAllow},
			responseHeadersResult: model.Result{
				Decision: model.DecisionError,
				Err:      errors.New("synthetic response headers failure"),
			},
		}
		service := newStubService(t, map[string]ProfileRuntime{
			"strict": newStubRuntime("strict", stub, model.ThresholdInfo{}, model.ThresholdInfo{}),
		}, "strict")

		state := service.newStreamState()
		_, _ = service.handleMessage(state, requestHeadersMessageWithEndOfStream("/ok", nil, true))
		result, resp := service.handleMessage(state, &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &extprocv3.HttpHeaders{
					Headers: headerMap(":status", "200"),
				},
			},
		})
		if result.Decision != model.DecisionAllow {
			t.Fatalf("expected allow decision, got %q", result.Decision)
		}
		if resp.GetResponseHeaders() == nil {
			t.Fatal("expected continue response headers response")
		}
	})

	t.Run("response body", func(t *testing.T) {
		stub := &stubSession{
			requestHeadersResult:  model.Result{Decision: model.DecisionAllow},
			responseHeadersResult: model.Result{Decision: model.DecisionAllow},
			responseBodyResult: model.Result{
				Decision: model.DecisionError,
				Err:      errors.New("synthetic response body failure"),
			},
		}
		service := newStubService(t, map[string]ProfileRuntime{
			"strict": newStubRuntime("strict", stub, model.ThresholdInfo{}, model.ThresholdInfo{}),
		}, "strict")

		state := service.newStreamState()
		_, _ = service.handleMessage(state, requestHeadersMessageWithEndOfStream("/ok", nil, true))
		_, _ = service.handleMessage(state, &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &extprocv3.HttpHeaders{
					Headers: headerMap(":status", "200"),
				},
			},
		})
		result, resp := service.handleMessage(state, &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        []byte("payload"),
					EndOfStream: true,
				},
			},
		})
		if result.Decision != model.DecisionAllow {
			t.Fatalf("expected allow decision, got %q", result.Decision)
		}
		if resp.GetResponseBody() == nil {
			t.Fatal("expected continue response body response")
		}
	})
}

func requestHeadersMessage(path string, attributes map[string]*structpb.Struct) *extprocv3.ProcessingRequest {
	return requestHeadersMessageWithEndOfStream(path, attributes, false)
}

func requestHeadersMessageWithEndOfStream(path string, attributes map[string]*structpb.Struct, endOfStream bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				EndOfStream: endOfStream,
				Headers: headerMap(
					":method", "GET",
					":path", path,
					":authority", "podinfo.klawu.com",
				),
			},
		},
		Attributes: attributes,
	}
}

func routeMetadataAttributes(annotationKey string, value string) map[string]*structpb.Struct {
	routeMetadata := mustStruct(map[string]any{
		"filter_metadata": map[string]any{
			"envoy-gateway": map[string]any{
				"resources": []any{
					map[string]any{
						"annotations": map[string]any{
							annotationKey: value,
						},
					},
				},
			},
		},
	})
	return map[string]*structpb.Struct{
		"xds.route_metadata": routeMetadata,
	}
}

func routeMetadataUnderExtProcNamespaceAttributes(annotationKey string, value string) map[string]*structpb.Struct {
	return map[string]*structpb.Struct{
		"envoy.filters.http.ext_proc": mustStruct(map[string]any{
			"xds": map[string]any{
				"route_metadata": map[string]any{
					"filter_metadata": map[string]any{
						"envoy-gateway": map[string]any{
							"resources": []any{
								map[string]any{
									"annotations": map[string]any{
										annotationKey: value,
									},
								},
							},
						},
					},
				},
			},
		}),
	}
}

func routeMetadataTextUnderExtProcNamespaceAttributes(annotationKey string, value string) map[string]*structpb.Struct {
	return map[string]*structpb.Struct{
		"envoy.filters.http.ext_proc": mustStruct(map[string]any{
			"xds.route_metadata": `filter_metadata { key: "envoy-gateway" value { fields { key: "resources" value { list_value { values { struct_value { fields { key: "annotations" value { struct_value { fields { key: "` + annotationKey + `" value { string_value: "` + value + `" } } } } } } } } } } }`,
		}),
	}
}

func mustStruct(input map[string]any) *structpb.Struct {
	st, err := structpb.NewStruct(input)
	if err != nil {
		panic(err)
	}
	return st
}

func headerMap(kv ...string) *corev3.HeaderMap {
	headers := make([]*corev3.HeaderValue, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		headers = append(headers, &corev3.HeaderValue{
			Key:      kv[i],
			RawValue: []byte(kv[i+1]),
		})
	}
	return &corev3.HeaderMap{Headers: headers}
}

type stubSession struct {
	requestHeadersResult  model.Result
	requestBodyResult     model.Result
	responseHeadersResult model.Result
	responseBodyResult    model.Result
	requestHeadersCalls   int
	requestBodyCalls      int
	responseHeadersCalls  int
	responseBodyCalls     int
}

func (s *stubSession) ProcessRequestHeaders() model.Result {
	s.requestHeadersCalls++
	return s.requestHeadersResult
}

func (s *stubSession) ProcessRequestBodyChunk([]byte, bool) model.Result {
	s.requestBodyCalls++
	return s.requestBodyResult
}

func (s *stubSession) ProcessResponseHeaders(int, string, []model.Header) model.Result {
	s.responseHeadersCalls++
	return s.responseHeadersResult
}

func (s *stubSession) ProcessResponseBodyChunk([]byte, bool) model.Result {
	s.responseBodyCalls++
	return s.responseBodyResult
}

func (s *stubSession) Close() {}

type capturingRecorder struct {
	request model.Request
	result  model.Result
	called  bool
}

func (r *capturingRecorder) Record(req model.Request, result model.Result) {
	r.request = req
	r.result = result
	r.called = true
}

type stubProcessStream struct {
	extprocv3.ExternalProcessor_ProcessServer
	recvMessages        []*extprocv3.ProcessingRequest
	recvIndex           int
	recvErr             error
	sent                []*extprocv3.ProcessingResponse
	responseBodyEosSeen bool
}

func (s *stubProcessStream) Send(resp *extprocv3.ProcessingResponse) error {
	s.sent = append(s.sent, resp)
	return nil
}

func (s *stubProcessStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if s.recvIndex < len(s.recvMessages) {
		msg := s.recvMessages[s.recvIndex]
		s.recvIndex++
		if rb := msg.GetResponseBody(); rb != nil && rb.GetEndOfStream() {
			s.responseBodyEosSeen = true
		}
		return msg, nil
	}
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	return nil, io.EOF
}

func (s *stubProcessStream) Context() context.Context     { return context.Background() }
func (s *stubProcessStream) SetHeader(metadata.MD) error  { return nil }
func (s *stubProcessStream) SendHeader(metadata.MD) error { return nil }
func (s *stubProcessStream) SetTrailer(metadata.MD)       {}
func (s *stubProcessStream) SendMsg(any) error            { return nil }
func (s *stubProcessStream) RecvMsg(any) error            { return nil }

func newEvaluatorRuntime(t *testing.T, name string, directives string) ProfileRuntime {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	evaluator, err := waf.NewEvaluatorWithDirectives(directives, logger)
	if err != nil {
		t.Fatalf("new evaluator: %v", err)
	}
	runtime, err := NewProfileRuntime(name, evaluator)
	if err != nil {
		t.Fatalf("new profile runtime: %v", err)
	}
	return runtime
}

func newStubRuntime(
	name string,
	stub Session,
	inboundThreshold model.ThresholdInfo,
	outboundThreshold model.ThresholdInfo,
) ProfileRuntime {
	return ProfileRuntime{
		Name: name,
		NewSession: func(model.Request) Session {
			return stub
		},
		ThresholdForAction: func(action model.ProcessingAction) model.ThresholdInfo {
			switch action {
			case model.ActionRequestHeaders, model.ActionRequestBody:
				return inboundThreshold
			case model.ActionResponseHeaders, model.ActionResponseBody:
				return outboundThreshold
			default:
				return model.ThresholdInfo{Source: model.ThresholdSourceUnknown}
			}
		},
	}
}

func newEvaluatorService(t *testing.T, profiles map[string]ProfileRuntime, defaultProfile string) *Service {
	t.Helper()
	service, err := NewService(profiles, defaultProfile, noopRecorder{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func newStubService(t *testing.T, profiles map[string]ProfileRuntime, defaultProfile string) *Service {
	t.Helper()
	service, err := NewService(profiles, defaultProfile, noopRecorder{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func (s *Service) newStreamState() *streamState {
	return pipeline.NewStreamState(s.defaultProfile, s.profiles[s.defaultProfile])
}
