package protoio

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func TestImmediateDenyResponseUsesWAFHeaders(t *testing.T) {
	resp := ImmediateDenyResponse(model.EngineModeBlock, model.Result{
		Decision:       model.DecisionDeny,
		HTTPStatusCode: 403,
		Interruption: &model.Interruption{
			RuleID: 942100,
		},
	})

	immediate := resp.GetImmediateResponse()
	if immediate == nil {
		t.Fatal("expected immediate response")
	}

	setHeaders := immediate.GetHeaders().GetSetHeaders()
	if len(setHeaders) == 0 {
		t.Fatal("expected deny headers")
	}

	headers := map[string]string{}
	for _, header := range setHeaders {
		headers[header.GetHeader().GetKey()] = string(header.GetHeader().GetRawValue())
	}

	if got := headers["x-waf-mode"]; got != string(model.EngineModeBlock) {
		t.Fatalf("expected x-waf-mode=block, got %q", got)
	}
	if got := headers["x-waf-rule-id"]; got != "942100" {
		t.Fatalf("expected x-waf-rule-id=942100, got %q", got)
	}
}

func TestResponseForUnknownActionReturnsInternalError(t *testing.T) {
	resp := ResponseForAction(model.ActionUnknown, model.EngineModeBlock, model.Result{
		Decision: model.DecisionAllow,
	})
	immediate := resp.GetImmediateResponse()
	if immediate == nil {
		t.Fatal("expected immediate response for unknown action")
	}
	if got := immediate.GetStatus().GetCode(); got != typev3.StatusCode_ServiceUnavailable {
		t.Fatalf("expected 503 status code, got %s", got.String())
	}
}

func TestParseRequestHeaders(t *testing.T) {
	request := ParseRequestHeaders(&extprocv3.HttpHeaders{
		Headers: &corev3.HeaderMap{
			Headers: []*corev3.HeaderValue{
				{Key: ":method", RawValue: []byte("POST")},
				{Key: ":path", RawValue: []byte("/login?q=1")},
				{Key: ":authority", RawValue: []byte("podinfo.klawu.com")},
				{Key: "x-request-id", RawValue: []byte("rid-1")},
				{Key: "x-forwarded-for", RawValue: []byte("1.1.1.1, 2.2.2.2")},
				{Key: "content-type", RawValue: []byte("application/json")},
			},
		},
	})

	if request.Method != "POST" {
		t.Fatalf("expected method POST, got %q", request.Method)
	}
	if request.Path != "/login" {
		t.Fatalf("expected path /login, got %q", request.Path)
	}
	if request.Query != "q=1" {
		t.Fatalf("expected query q=1, got %q", request.Query)
	}
	if request.Host != "podinfo.klawu.com" {
		t.Fatalf("expected host podinfo.klawu.com, got %q", request.Host)
	}
	if request.ID != "rid-1" {
		t.Fatalf("expected request id rid-1, got %q", request.ID)
	}
	if request.ClientIP != "1.1.1.1" {
		t.Fatalf("expected first client ip 1.1.1.1, got %q", request.ClientIP)
	}
}
