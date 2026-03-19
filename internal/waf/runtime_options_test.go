package waf

import (
	"strings"
	"testing"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func TestBuildRuntimeDirectivesBaseline(t *testing.T) {
	directives, inbound, outbound, err := buildRuntimeDirectives(RuntimeOptions{})
	if err != nil {
		t.Fatalf("build runtime directives: %v", err)
	}

	if !strings.Contains(directives, "Include @coraza.conf-recommended") {
		t.Fatalf("expected baseline directives, got: %s", directives)
	}
	if !strings.Contains(directives, "Include @owasp_crs/*.conf") {
		t.Fatalf("expected CRS include, got: %s", directives)
	}
	if !strings.Contains(directives, "SecResponseBodyLimitAction Reject") {
		t.Fatalf("expected response body limit action reject, got: %s", directives)
	}
	if inbound.Source == "" || outbound.Source == "" {
		t.Fatalf("expected threshold sources to be populated, got inbound=%q outbound=%q", inbound.Source, outbound.Source)
	}
}

func TestBuildRuntimeDirectivesWithRuleExclusions(t *testing.T) {
	directives, _, _, err := buildRuntimeDirectives(RuntimeOptions{
		ExcludedRuleIDs: []int{941130, 942100},
	})
	if err != nil {
		t.Fatalf("build runtime directives: %v", err)
	}

	if !strings.Contains(directives, "SecRuleRemoveById 941130") {
		t.Fatalf("expected rule exclusion for 941130, got: %s", directives)
	}
	if !strings.Contains(directives, "SecRuleRemoveById 942100") {
		t.Fatalf("expected rule exclusion for 942100, got: %s", directives)
	}
	includeIdx := strings.Index(directives, "Include @owasp_crs/*.conf")
	removeIdx := strings.Index(directives, "SecRuleRemoveById 941130")
	if includeIdx == -1 || removeIdx == -1 || removeIdx < includeIdx {
		t.Fatalf("expected rule removal after CRS include, got: %s", directives)
	}
}

func TestBuildRuntimeDirectivesWithThresholdOverrides(t *testing.T) {
	directives, inbound, outbound, err := buildRuntimeDirectives(RuntimeOptions{
		InboundAnomalyThreshold:  intPtr(9),
		OutboundAnomalyThreshold: intPtr(8),
	})
	if err != nil {
		t.Fatalf("build runtime directives: %v", err)
	}

	if !strings.Contains(directives, "tx.inbound_anomaly_score_threshold=9") {
		t.Fatalf("expected inbound threshold override directive, got: %s", directives)
	}
	if !strings.Contains(directives, "tx.outbound_anomaly_score_threshold=8") {
		t.Fatalf("expected outbound threshold override directive, got: %s", directives)
	}

	if inbound.Source != model.ThresholdSourceEnvOverride {
		t.Fatalf("expected inbound env override source, got %q", inbound.Source)
	}
	if outbound.Source != model.ThresholdSourceEnvOverride {
		t.Fatalf("expected outbound env override source, got %q", outbound.Source)
	}
	if inbound.Value == nil || *inbound.Value != 9 {
		t.Fatalf("unexpected inbound threshold value: %+v", inbound.Value)
	}
	if outbound.Value == nil || *outbound.Value != 8 {
		t.Fatalf("unexpected outbound threshold value: %+v", outbound.Value)
	}
}

func TestBuildRuntimeDirectivesCombined(t *testing.T) {
	directives, inbound, outbound, err := buildRuntimeDirectives(RuntimeOptions{
		BlockingParanoiaLevel:    intPtr(2),
		DetectionParanoiaLevel:   intPtr(3),
		ExcludedRuleIDs:          []int{941130},
		InboundAnomalyThreshold:  intPtr(7),
		OutboundAnomalyThreshold: intPtr(6),
		ResponseBodyMIMETypes:    []string{"application/json", "text/plain"},
		EarlyBlocking:            true,
	})
	if err != nil {
		t.Fatalf("build runtime directives: %v", err)
	}

	assertContains(t, directives, "SecRuleRemoveById 941130")
	assertContains(t, directives, "tx.inbound_anomaly_score_threshold=7")
	assertContains(t, directives, "tx.outbound_anomaly_score_threshold=6")
	assertContains(t, directives, "tx.blocking_paranoia_level=2")
	assertContains(t, directives, "tx.detection_paranoia_level=3")
	assertContains(t, directives, "tx.early_blocking=1")
	assertContains(t, directives, "SecResponseBodyMimeType application/json text/plain")
	if inbound.Source != model.ThresholdSourceEnvOverride || outbound.Source != model.ThresholdSourceEnvOverride {
		t.Fatalf("unexpected threshold sources: inbound=%q outbound=%q", inbound.Source, outbound.Source)
	}
}

func TestBuildRuntimeDirectivesParanoiaLevelsBeforeCRSInclude(t *testing.T) {
	directives, _, _, err := buildRuntimeDirectives(RuntimeOptions{
		BlockingParanoiaLevel:  intPtr(2),
		DetectionParanoiaLevel: intPtr(4),
	})
	if err != nil {
		t.Fatalf("build runtime directives: %v", err)
	}

	blockingIdx := strings.Index(directives, "tx.blocking_paranoia_level=2")
	detectionIdx := strings.Index(directives, "tx.detection_paranoia_level=4")
	includeIdx := strings.Index(directives, "Include @owasp_crs/*.conf")
	if blockingIdx == -1 || detectionIdx == -1 || includeIdx == -1 {
		t.Fatalf("expected paranoia directives and CRS include, got: %s", directives)
	}
	if blockingIdx > includeIdx || detectionIdx > includeIdx {
		t.Fatalf("expected paranoia directives before CRS include, got: %s", directives)
	}
}

func TestBuildRuntimeDirectivesWithoutEarlyBlocking(t *testing.T) {
	directives, _, _, err := buildRuntimeDirectives(RuntimeOptions{})
	if err != nil {
		t.Fatalf("build runtime directives: %v", err)
	}
	if strings.Contains(directives, "tx.early_blocking=1") {
		t.Fatalf("did not expect early blocking directive by default, got: %s", directives)
	}
}

func assertContains(t *testing.T, haystack string, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("expected %q in directives", needle)
	}
}

func intPtr(value int) *int {
	return &value
}
