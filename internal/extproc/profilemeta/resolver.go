package profilemeta

import (
	"context"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/ilyasaftr/coraza-envoy-waf/internal/extproc/runtime"
	"google.golang.org/protobuf/encoding/protojson"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

const maxProfileLookupDepth = 32

var profileAnnotationKeys = []string{
	"coraza-profile",
	"gateway.envoyproxy.io/coraza-profile",
}

var profileFromMetadataTextPatterns = buildProfileFromMetadataTextPatterns()

type Resolver struct {
	profiles       map[string]runtime.ProfileRuntime
	defaultProfile string
	logger         *slog.Logger
}

func NewResolver(profiles map[string]runtime.ProfileRuntime, defaultProfile string, logger *slog.Logger) *Resolver {
	if logger == nil {
		logger = slog.Default()
	}
	return &Resolver{
		profiles:       profiles,
		defaultProfile: defaultProfile,
		logger:         logger,
	}
}

func (r *Resolver) Resolve(msg *extprocv3.ProcessingRequest) (string, runtime.ProfileRuntime) {
	candidate, found := ExtractProfileName(msg)
	if !found {
		r.logger.Debug("missing coraza profile metadata; using default profile", "default_profile", r.defaultProfile)
		return r.defaultProfile, r.profiles[r.defaultProfile]
	}

	profile, ok := r.profiles[candidate]
	if !ok {
		r.logger.Warn("unknown coraza profile; using default profile", "profile", candidate, "default_profile", r.defaultProfile)
		return r.defaultProfile, r.profiles[r.defaultProfile]
	}

	return candidate, profile
}

func LogRequestAttributes(logger *slog.Logger, msg *extprocv3.ProcessingRequest) {
	if logger == nil || msg == nil {
		return
	}
	if !logger.Enabled(context.Background(), slog.LevelDebug) {
		return
	}

	keys := make([]string, 0, len(msg.GetAttributes()))
	sanitizedByKey := make(map[string]string, len(msg.GetAttributes()))
	for key := range msg.GetAttributes() {
		keys = append(keys, key)
		sanitizedByKey[key] = sanitizeStructForLog(msg.GetAttributes()[key])
	}
	slices.Sort(keys)

	logger.Debug(
		"ext_proc request attributes",
		"attributes_keys", keys,
		"attributes_payload", sanitizedByKey,
	)
}

func ExtractProfileName(msg *extprocv3.ProcessingRequest) (string, bool) {
	if msg == nil {
		return "", false
	}

	if routeMetadata, ok := msg.GetAttributes()["xds.route_metadata"]; ok {
		if profileName, ok := extractProfileNameFromStruct(routeMetadata); ok {
			return profileName, true
		}
	}
	for _, attr := range msg.GetAttributes() {
		if profileName, ok := extractProfileNameFromStruct(attr); ok {
			return profileName, true
		}
	}

	metadataContext := msg.GetMetadataContext()
	if metadataContext == nil {
		return "", false
	}
	for _, value := range metadataContext.GetFilterMetadata() {
		if profileName, ok := extractProfileNameFromStruct(value); ok {
			return profileName, true
		}
	}

	return "", false
}

func extractProfileNameFromStruct(meta *structpb.Struct) (string, bool) {
	if meta == nil {
		return "", false
	}
	return extractProfileFromFields(meta.Fields, 0)
}

func extractProfileFromFields(fields map[string]*structpb.Value, depth int) (string, bool) {
	if depth > maxProfileLookupDepth {
		return "", false
	}

	if annotationsValue, ok := fields["annotations"]; ok {
		if profileName, found := profileNameFromAnnotationsValue(annotationsValue); found {
			return profileName, true
		}
	}

	for _, value := range fields {
		if profileName, found := extractProfileFromValue(value, depth+1); found {
			return profileName, true
		}
	}

	return "", false
}

func extractProfileFromValue(value *structpb.Value, depth int) (string, bool) {
	if value == nil || depth > maxProfileLookupDepth {
		return "", false
	}

	switch kind := value.Kind.(type) {
	case *structpb.Value_StructValue:
		return extractProfileFromFields(kind.StructValue.GetFields(), depth+1)
	case *structpb.Value_ListValue:
		for _, item := range kind.ListValue.GetValues() {
			if profileName, found := extractProfileFromValue(item, depth+1); found {
				return profileName, true
			}
		}
	case *structpb.Value_StringValue:
		return profileNameFromMetadataText(kind.StringValue)
	}

	return "", false
}

func profileNameFromAnnotationsValue(value *structpb.Value) (string, bool) {
	if value == nil {
		return "", false
	}
	annotationStruct := value.GetStructValue()
	if annotationStruct == nil {
		return "", false
	}
	for _, key := range profileAnnotationKeys {
		if rawValue, ok := annotationStruct.GetFields()[key]; ok {
			profileName := strings.TrimSpace(rawValue.GetStringValue())
			if profileName != "" {
				return profileName, true
			}
		}
	}
	return "", false
}

func buildProfileFromMetadataTextPatterns() []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, 0, len(profileAnnotationKeys))
	for _, key := range profileAnnotationKeys {
		pattern := `(?s)key:\s*"` + regexp.QuoteMeta(key) + `"\s*value\s*{\s*string_value:\s*"([^"]+)"`
		patterns = append(patterns, regexp.MustCompile(pattern))
	}
	return patterns
}

func profileNameFromMetadataText(text string) (string, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", false
	}

	for _, pattern := range profileFromMetadataTextPatterns {
		matches := pattern.FindStringSubmatch(text)
		if len(matches) < 2 {
			continue
		}
		profileName := strings.TrimSpace(matches[1])
		if profileName != "" {
			return profileName, true
		}
	}
	return "", false
}

func sanitizeStructForLog(meta *structpb.Struct) string {
	if meta == nil {
		return ""
	}
	payload, err := protojson.Marshal(meta)
	if err != nil {
		return "<marshal_error>"
	}
	const maxLen = 4096
	text := string(payload)
	if len(text) > maxLen {
		return text[:maxLen] + "...(truncated)"
	}
	return text
}
