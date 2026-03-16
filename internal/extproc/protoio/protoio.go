package protoio

import (
	"errors"
	"strconv"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func ParseRequestHeaders(httpHeaders *extprocv3.HttpHeaders, mode model.Mode) model.Request {
	request := model.Request{
		ID:       strconv.FormatInt(time.Now().UnixNano(), 10),
		Method:   "GET",
		Path:     "/",
		Protocol: "HTTP/1.1",
		Mode:     mode,
	}
	if httpHeaders == nil || httpHeaders.GetHeaders() == nil {
		return request
	}

	rawHeaders := httpHeaders.GetHeaders().GetHeaders()
	request.Headers = make([]model.Header, 0, len(rawHeaders))
	for _, rawHeader := range rawHeaders {
		key, value := headerKeyValue(rawHeader)
		switch key {
		case ":method":
			if value != "" {
				request.Method = value
			}
		case ":path":
			request.Path, request.Query = splitPathAndQuery(value)
		case ":authority", "host":
			if request.Host == "" && value != "" {
				request.Host = value
			}
		case "x-request-id":
			if value != "" {
				request.ID = value
			}
		case "x-forwarded-for":
			request.ClientIP = firstClientIP(value)
		default:
			if !strings.HasPrefix(key, ":") {
				request.Headers = append(request.Headers, model.Header{
					Key:   key,
					Value: value,
				})
			}
		}
	}

	return request
}

func ParseResponseHeaders(httpHeaders *extprocv3.HttpHeaders) (int, string, []model.Header) {
	statusCode := 200
	protocol := "HTTP/1.1"
	headers := []model.Header{}
	if httpHeaders == nil || httpHeaders.GetHeaders() == nil {
		return statusCode, protocol, headers
	}

	rawHeaders := httpHeaders.GetHeaders().GetHeaders()
	headers = make([]model.Header, 0, len(rawHeaders))
	for _, rawHeader := range rawHeaders {
		key, value := headerKeyValue(rawHeader)
		switch key {
		case ":status":
			if code, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
				statusCode = code
			}
		case ":protocol":
			if value != "" {
				protocol = value
			}
		default:
			if !strings.HasPrefix(key, ":") {
				headers = append(headers, model.Header{
					Key:   key,
					Value: value,
				})
			}
		}
	}
	return statusCode, protocol, headers
}

func ContinueTrailersResponse(isRequest bool) *extprocv3.ProcessingResponse {
	if isRequest {
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestTrailers{
				RequestTrailers: &extprocv3.TrailersResponse{},
			},
		}
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &extprocv3.TrailersResponse{},
		},
	}
}

func ResponseForAction(action model.ProcessingAction, mode model.Mode, result model.Result) *extprocv3.ProcessingResponse {
	if shouldDeny(result) {
		return ImmediateDenyResponse(mode, result)
	}

	switch action {
	case model.ActionRequestHeaders:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestHeaders{
				RequestHeaders: continueHeadersResponse(),
			},
		}
	case model.ActionRequestBody:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestBody{
				RequestBody: continueBodyResponse(),
			},
		}
	case model.ActionResponseHeaders:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: continueHeadersResponse(),
			},
		}
	case model.ActionResponseBody:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_ResponseBody{
				ResponseBody: continueBodyResponse(),
			},
		}
	default:
		unknown := model.Result{
			Decision:       model.DecisionError,
			HTTPStatusCode: 503,
			Body:           "internal authorization error",
			Err:            errors.New("unknown processing action"),
		}
		return ImmediateDenyResponse(mode, unknown)
	}
}

func ImmediateDenyResponse(mode model.Mode, result model.Result) *extprocv3.ProcessingResponse {
	statusCode := result.HTTPStatusCode
	if statusCode <= 0 {
		if result.Decision == model.DecisionError {
			statusCode = 503
		} else {
			statusCode = 403
		}
	}

	body := result.Body
	if body == "" {
		if result.Decision == model.DecisionError {
			body = "internal authorization error"
		} else {
			body = "blocked by coraza waf"
		}
	}

	ruleID := result.RuleID
	if ruleID == "" && result.Interruption != nil {
		ruleID = strconv.Itoa(result.Interruption.RuleID)
	}
	if ruleID == "" {
		ruleID = "0"
	}

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{
					Code: httpStatusCode(statusCode),
				},
				Body: []byte(body),
				Headers: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						{
							Header: &corev3.HeaderValue{
								Key:      "x-waf-mode",
								RawValue: []byte(mode),
							},
						},
						{
							Header: &corev3.HeaderValue{
								Key:      "x-waf-rule-id",
								RawValue: []byte(ruleID),
							},
						},
					},
				},
				Details: "coraza_ext_proc_interruption",
			},
		},
	}
}

func shouldDeny(result model.Result) bool {
	return result.Decision == model.DecisionDeny || result.Decision == model.DecisionError
}

func continueHeadersResponse() *extprocv3.HeadersResponse {
	return &extprocv3.HeadersResponse{
		Response: &extprocv3.CommonResponse{
			Status: extprocv3.CommonResponse_CONTINUE,
		},
	}
}

func continueBodyResponse() *extprocv3.BodyResponse {
	return &extprocv3.BodyResponse{
		Response: &extprocv3.CommonResponse{
			Status: extprocv3.CommonResponse_CONTINUE,
		},
	}
}

func headerKeyValue(header *corev3.HeaderValue) (string, string) {
	if header == nil {
		return "", ""
	}
	value := header.GetValue()
	if value == "" && len(header.GetRawValue()) > 0 {
		value = string(header.GetRawValue())
	}
	return strings.ToLower(header.GetKey()), value
}

func splitPathAndQuery(rawPath string) (string, string) {
	if rawPath == "" {
		return "/", ""
	}

	path := rawPath
	query := ""
	if idx := strings.Index(rawPath, "?"); idx >= 0 {
		path = rawPath[:idx]
		query = rawPath[idx+1:]
	}
	if path == "" {
		path = "/"
	}
	return path, query
}

func firstClientIP(value string) string {
	if idx := strings.IndexByte(value, ','); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func httpStatusCode(code int) typev3.StatusCode {
	switch code {
	case 400:
		return typev3.StatusCode_BadRequest
	case 401:
		return typev3.StatusCode_Unauthorized
	case 403:
		return typev3.StatusCode_Forbidden
	case 404:
		return typev3.StatusCode_NotFound
	case 413:
		return typev3.StatusCode_PayloadTooLarge
	case 429:
		return typev3.StatusCode_TooManyRequests
	case 500:
		return typev3.StatusCode_InternalServerError
	case 503:
		return typev3.StatusCode_ServiceUnavailable
	default:
		return typev3.StatusCode_InternalServerError
	}
}
