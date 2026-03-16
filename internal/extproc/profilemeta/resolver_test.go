package profilemeta

import (
	"context"
	"io"
	"log/slog"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/runtime"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

func TestExtractProfileNameFromRouteMetadataShortKey(t *testing.T) {
	msg := &extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{
			"xds.route_metadata": mustStruct(map[string]any{
				"filter_metadata": map[string]any{
					"envoy-gateway": map[string]any{
						"resources": []any{
							map[string]any{
								"annotations": map[string]any{
									"coraza-profile": "strict",
								},
							},
						},
					},
				},
			}),
		},
	}

	profileName, found := ExtractProfileName(msg)
	if !found {
		t.Fatal("expected profile to be found")
	}
	if profileName != "strict" {
		t.Fatalf("expected profile strict, got %q", profileName)
	}
}

func TestExtractProfileNameFromNamespacedAttributes(t *testing.T) {
	msg := &extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{
			"envoy.filters.http.ext_proc": mustStruct(map[string]any{
				"xds": map[string]any{
					"route_metadata": map[string]any{
						"filter_metadata": map[string]any{
							"envoy-gateway": map[string]any{
								"resources": []any{
									map[string]any{
										"annotations": map[string]any{
											"coraza-profile": "strict",
										},
									},
								},
							},
						},
					},
				},
			}),
		},
	}

	profileName, found := ExtractProfileName(msg)
	if !found {
		t.Fatal("expected profile to be found")
	}
	if profileName != "strict" {
		t.Fatalf("expected profile strict, got %q", profileName)
	}
}

func TestExtractProfileNameFromNamespacedAttributesTextMetadata(t *testing.T) {
	msg := &extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{
			"envoy.filters.http.ext_proc": mustStruct(map[string]any{
				"xds.route_metadata": `filter_metadata { key: "envoy-gateway" value { fields { key: "resources" value { list_value { values { struct_value { fields { key: "annotations" value { struct_value { fields { key: "coraza-profile" value { string_value: "strict" } } } } } } } } } } }`,
			}),
		},
	}

	profileName, found := ExtractProfileName(msg)
	if !found {
		t.Fatal("expected profile to be found")
	}
	if profileName != "strict" {
		t.Fatalf("expected profile strict, got %q", profileName)
	}
}

func TestExtractProfileNameFromMetadataContext(t *testing.T) {
	msg := &extprocv3.ProcessingRequest{
		MetadataContext: &corev3.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				"envoy-gateway": mustStruct(map[string]any{
					"resources": []any{
						map[string]any{
							"annotations": map[string]any{
								"gateway.envoyproxy.io/coraza-profile": "strict",
							},
						},
					},
				}),
			},
		},
	}

	profileName, found := ExtractProfileName(msg)
	if !found {
		t.Fatal("expected profile to be found")
	}
	if profileName != "strict" {
		t.Fatalf("expected profile strict, got %q", profileName)
	}
}

func TestResolverFallsBackToDefault(t *testing.T) {
	profiles := map[string]runtime.ProfileRuntime{
		"default": {
			Name: "default",
			Mode: model.ModeDetect,
			NewSession: func(model.Request) runtime.Session {
				return stubSession{}
			},
		},
		"strict": {
			Name: "strict",
			Mode: model.ModeBlock,
			NewSession: func(model.Request) runtime.Session {
				return stubSession{}
			},
		},
	}

	resolver := NewResolver(profiles, "default", slog.New(slog.NewTextHandler(io.Discard, nil)))
	name, profile := resolver.Resolve(&extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{
			"xds.route_metadata": mustStruct(map[string]any{
				"filter_metadata": map[string]any{
					"envoy-gateway": map[string]any{
						"resources": []any{
							map[string]any{
								"annotations": map[string]any{
									"coraza-profile": "missing",
								},
							},
						},
					},
				},
			}),
		},
	})
	if name != "default" {
		t.Fatalf("expected default profile, got %q", name)
	}
	if profile.Mode != model.ModeDetect {
		t.Fatalf("expected default profile mode detect, got %q", profile.Mode)
	}
}

func TestLogRequestAttributesSkipsWhenDebugDisabled(t *testing.T) {
	handler := &resolverCaptureHandler{minLevel: slog.LevelInfo}
	logger := slog.New(handler)

	LogRequestAttributes(logger, &extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{
			"xds.route_metadata": mustStruct(map[string]any{
				"filter_metadata": map[string]any{
					"envoy-gateway": map[string]any{
						"resources": []any{map[string]any{"annotations": map[string]any{"coraza-profile": "strict"}}},
					},
				},
			}),
		},
	})

	if got := len(handler.entries); got != 0 {
		t.Fatalf("expected no debug logs when debug disabled, got %d", got)
	}
}

func TestLogRequestAttributesLogsWhenDebugEnabled(t *testing.T) {
	handler := &resolverCaptureHandler{minLevel: slog.LevelDebug}
	logger := slog.New(handler)

	LogRequestAttributes(logger, &extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{
			"xds.route_metadata": mustStruct(map[string]any{
				"filter_metadata": map[string]any{
					"envoy-gateway": map[string]any{
						"resources": []any{map[string]any{"annotations": map[string]any{"coraza-profile": "strict"}}},
					},
				},
			}),
		},
	})

	if got := len(handler.entries); got != 1 {
		t.Fatalf("expected one debug log entry, got %d", got)
	}
	if got := handler.entries[0].attrs["attributes_keys"]; got == nil {
		t.Fatalf("expected attributes_keys in debug log, got %#v", handler.entries[0].attrs)
	}
	if got := handler.entries[0].attrs["attributes_payload"]; got == nil {
		t.Fatalf("expected attributes_payload in debug log, got %#v", handler.entries[0].attrs)
	}
}

func mustStruct(input map[string]any) *structpb.Struct {
	st, err := structpb.NewStruct(input)
	if err != nil {
		panic(err)
	}
	return st
}

type stubSession struct{}

func (stubSession) ProcessRequestHeaders() model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (stubSession) ProcessRequestBodyChunk([]byte, bool) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (stubSession) ProcessResponseHeaders(int, string, []model.Header) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (stubSession) ProcessResponseBodyChunk([]byte, bool) model.Result {
	return model.Result{Decision: model.DecisionAllow}
}

func (stubSession) Close() {}

type resolverCapturedLog struct {
	attrs map[string]any
}

type resolverCaptureHandler struct {
	minLevel slog.Level
	entries  []resolverCapturedLog
}

func (h *resolverCaptureHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.minLevel
}

func (h *resolverCaptureHandler) Handle(_ context.Context, record slog.Record) error {
	entry := resolverCapturedLog{attrs: map[string]any{}}
	record.Attrs(func(attr slog.Attr) bool {
		entry.attrs[attr.Key] = attrValue(attr.Value)
		return true
	})
	h.entries = append(h.entries, entry)
	return nil
}

func (h *resolverCaptureHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *resolverCaptureHandler) WithGroup(_ string) slog.Handler {
	return h
}

func attrValue(value slog.Value) any {
	switch value.Kind() {
	case slog.KindString:
		return value.String()
	case slog.KindInt64:
		return value.Int64()
	case slog.KindUint64:
		return value.Uint64()
	case slog.KindBool:
		return value.Bool()
	case slog.KindFloat64:
		return value.Float64()
	case slog.KindAny:
		return value.Any()
	default:
		return value.Any()
	}
}
