package intyga

import (
	"strings"
	"testing"
)

func TestTrustAnchorTenantIDIsOptionalButValidated(t *testing.T) {
	base := `{"type":"intyga-trust-anchor","v":1,"epoch":1,"approvers":[{"did":"did:intyga:key:test","publicKeys":[]}]}`
	legacy, err := ParseTrustAnchorFile(base, TrustAnchorOnline)
	if err != nil || legacy.TenantID != "" {
		t.Fatalf("legacy trust anchor must remain valid: %+v %v", legacy, err)
	}
	bound := strings.Replace(base, `"epoch":1`, `"tenantId":"Tenant-A","epoch":1`, 1)
	parsed, err := ParseTrustAnchorFile(bound, TrustAnchorOnline)
	if err != nil || parsed.TenantID != "Tenant-A" {
		t.Fatalf("tenant-bound trust anchor was not preserved exactly: %+v %v", parsed, err)
	}
	invalid := strings.Replace(base, `"epoch":1`, `"tenantId":"","epoch":1`, 1)
	if _, err := ParseTrustAnchorFile(invalid, TrustAnchorOnline); err == nil || !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("empty trust-anchor tenantId was not refused clearly: %v", err)
	}
}
