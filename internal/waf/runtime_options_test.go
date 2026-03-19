package waf

import (
	"testing"

	"github.com/ilyasaftr/coraza-envoy-waf/internal/model"
)

func TestResolveThresholdMetadataFromDirectivesUsesProfileDirectives(t *testing.T) {
	inbound, outbound, err := resolveThresholdMetadataFromDirectives(`
SecRuleEngine On
SecAction "id:10000001,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=9"
SecAction "id:10000002,phase:1,pass,nolog,setvar:tx.outbound_anomaly_score_threshold=8"
`)
	if err != nil {
		t.Fatalf("resolve threshold metadata: %v", err)
	}

	if inbound.Source != model.ThresholdSourceProfileDirective {
		t.Fatalf("expected inbound profile directive source, got %q", inbound.Source)
	}
	if outbound.Source != model.ThresholdSourceProfileDirective {
		t.Fatalf("expected outbound profile directive source, got %q", outbound.Source)
	}
	if inbound.Value == nil || *inbound.Value != 9 {
		t.Fatalf("unexpected inbound threshold value: %+v", inbound.Value)
	}
	if outbound.Value == nil || *outbound.Value != 8 {
		t.Fatalf("unexpected outbound threshold value: %+v", outbound.Value)
	}
}

func TestResolveThresholdMetadataFromDirectivesFallsBackToCRSDefaults(t *testing.T) {
	inbound, outbound, err := resolveThresholdMetadataFromDirectives(`
SecRuleEngine DetectionOnly
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
`)
	if err != nil {
		t.Fatalf("resolve threshold metadata: %v", err)
	}
	if inbound.Source == model.ThresholdSourceUnknown || outbound.Source == model.ThresholdSourceUnknown {
		t.Fatalf("expected CRS defaults to resolve, got inbound=%q outbound=%q", inbound.Source, outbound.Source)
	}
}

func TestParseThresholdValueReturnsLastOverride(t *testing.T) {
	value := parseThresholdValue([]byte(`
SecAction "id:1,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=7"
SecAction "id:2,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=5"
`), inboundThresholdDirectivePattern)
	if value == nil || *value != 5 {
		t.Fatalf("expected last threshold value 5, got %+v", value)
	}
}
