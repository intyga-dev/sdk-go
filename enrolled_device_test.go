package intyga

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	verify "github.com/intyga-dev/sdk-go/v2/verify"
)

// DIV §4.3.2 "Enrolled approver devices" on the SDK side. The shared offline-approval vectors pin
// the bundle, requirement, challenge and trust-anchor behaviour; these tests pin what no vector
// reaches: rule selection, the delegation-weaker rule and the step-3d floor a bundle rule imposes.

func TestLostApprovalConstraintsTreatsEnrolledDeviceLikeHardware(t *testing.T) {
	base := PolicyRule{ActionPattern: "*", RequiredApprovals: 1, ApproverDids: []string{"did:a"}}
	device := base
	device.ActionPattern = "deploy.production"
	device.RequireEnrolledDevice = true

	if lost := LostApprovalConstraints(base, device); len(lost) != 1 || lost[0] != "requireEnrolledDevice" {
		t.Fatalf("dropping the requirement must be reported: %v", lost)
	}
	if lost := LostApprovalConstraints(device, base); len(lost) != 0 {
		t.Fatalf("adding the requirement is stricter, not lost: %v", lost)
	}
	// An exact rule cannot drop the baseline's enrolled-device requirement.
	baseline := device
	baseline.ActionPattern = "*"
	exact := base
	exact.ActionPattern = "db.restart"
	err := ValidateExactApprovalPolicy([]PolicyRule{baseline, exact})
	if err == nil || !strings.Contains(err.Error(), "requireEnrolledDevice") {
		t.Fatalf("an exact rule dropping the baseline's enrolled-device requirement must conflict: %v", err)
	}

	// Auto-approval compares the requirement for equality (absent == false).
	requester := "did:svc"
	auto := base
	auto.AutoApproveRequesterDid = &requester
	autoDevice := auto
	autoDevice.RequireEnrolledDevice = true
	if lost := LostApprovalConstraints(autoDevice, auto); !containsString(lost, "autoApproval") {
		t.Fatalf("auto-approval must compare requireEnrolledDevice: %v", lost)
	}
	if lost := LostApprovalConstraints(auto, auto); containsString(lost, "autoApproval") {
		t.Fatalf("identical auto-approval rules: %v", lost)
	}
}

func TestRequirementFloorOfCarriesEnrolledDevice(t *testing.T) {
	floor := requirementFloorOf(verify.ApprovalRequirement{RequiredApprovals: 2, SignerClass: "human", RequireEnrolledDevice: true})
	if !floor.RequireEnrolledDevice || floor.RequiredApprovals != 2 {
		t.Fatalf("floor: %+v", floor)
	}
	if floor := requirementFloorOf(verify.ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}); floor.RequireEnrolledDevice {
		t.Fatalf("absent must stay absent: %+v", floor)
	}
}

func TestTypedBundleV1RefusesEnrolledDeviceRule(t *testing.T) {
	V := loadOfflineVectors(t)
	bundle := V.bundle(t)
	for i := range bundle.Policy {
		if bundle.Policy[i].ActionPattern == "db.restart" {
			bundle.Policy[i].RequireEnrolledDevice = true
		}
	}
	bundle.V = 1
	if _, ok := RequirementFor(bundle, "db.restart", ""); ok {
		t.Fatal("a version 1 bundle never carries requireEnrolledDevice")
	}
	bundle.V = 2
	got, ok := RequirementFor(bundle, "db.restart", "")
	if !ok || !got.Requirement.RequireEnrolledDevice {
		t.Fatalf("version 2 must resolve and carry the requirement: ok=%v %+v", ok, got.Requirement)
	}
}

func TestDelegationIsWeakerThanAnEnrolledDeviceRule(t *testing.T) {
	V := loadOfflineVectors(t)
	action := OfflineAction{
		Target:     "prod-db-cluster-01",
		ActionType: "db.restart",
		Display:    "Restart the primary database — “eu-north” ✓",
		Params: map[string]interface{}{
			"cluster": "primary", "replicas": []interface{}{float64(1), float64(2)}, "force": false, "note": "åäö 🚀",
		},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sealed-ordinary.json"), V.Delegations["sealed-ordinary"], 0o600); err != nil {
		t.Fatal(err)
	}
	requester := verify.RequesterIdentity{DID: V.RequesterDID}
	asOf := mustTime(t, "2026-10-06T12:00:00.123Z")

	// Control: the same delegation applies under the vectors' own rule.
	if d, reason := findDelegation(dir, V.bundle(t), action, requester, asOf); d == nil {
		t.Fatalf("control: the vector delegation must apply: %s", reason)
	}
	bundle := V.bundle(t)
	bundle.V = 2
	for i := range bundle.Policy {
		if bundle.Policy[i].ActionPattern == "db.restart" {
			bundle.Policy[i].RequireEnrolledDevice = true
		}
	}
	d, reason := findDelegation(dir, bundle, action, requester, asOf)
	if d != nil || !strings.Contains(reason, "weaker") {
		t.Fatalf("a delegation can never meet an enrolled-device rule: %v %q", d, reason)
	}
}

func TestTrustAnchorEnrolledDeviceKeysIsACopy(t *testing.T) {
	if keys := TrustAnchorEnrolledDeviceKeys(nil); keys == nil || len(keys) != 0 {
		t.Fatalf("nil file: %v", keys)
	}
	file := &TrustAnchorFile{EnrolledDeviceKeys: []string{"a"}}
	keys := TrustAnchorEnrolledDeviceKeys(file)
	keys[0] = "b"
	if file.EnrolledDeviceKeys[0] != "a" {
		t.Fatal("the helper must not alias the parsed file")
	}
}

// The approval guard forwards the caller's enrolled device keys to verification (DIV §4.3.2):
// without them a receipt whose signed policy requires an enrolled device is refused before the tool
// runs; with them it executes. Mirrors the TS guard's enrolledDeviceKeys.
func TestGuardVerifiesAnEnrolledDeviceReceiptOnlyWithTheKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	spki := base64.StdEncoding.EncodeToString(der)
	params := map[string]interface{}{"amount": float64(4200), "currency": "USD"}
	requester := verify.RequesterIdentity{DID: "did:intyga:agent:payments"}
	requirement := verify.ApprovalRequirement{RequiredApprovals: 1, AllowedAaguids: []string{}, SignerClass: "human", RequireEnrolledDevice: true}
	canonical, err := verify.CanonicalIntentPayload("prod-payments", "payments.wire", "Wire USD 4,200", params, requester, requirement, "ed-guard-nonce", "2999-01-01T00:00:00.000Z")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(canonical))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	run := func(mutate func(*ApprovalGuardOptions)) (string, error, []string) {
		f := newGuardFixture(t)
		f.receipt = map[string]interface{}{
			"canonicalPayload": canonical, "actionDescription": "Wire USD 4,200", "params": params,
			"requester": map[string]interface{}{"did": requester.DID, "attestation": nil},
			"signerDid": "did:intyga:alice", "signerPublicKey": spki,
			"signature": base64.StdEncoding.EncodeToString(sig), "sigAlg": "ES256", "verificationCode": "000000",
		}
		f.nonce = "ed-guard-nonce"
		f.opts.Target, f.opts.ActionType = "prod-payments", "payments.wire"
		f.opts.Description = "Wire USD 4,200"
		f.opts.Approvers = verify.ApproverTrustAnchor{PublicKeys: []string{spki}}
		mutate(&f.opts)
		guard, err := NewApprovalGuard(f.client, f.opts, func(context.Context, map[string]interface{}) (string, error) {
			f.events = append(f.events, "tool")
			return "sent", nil
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := guard(context.Background(), map[string]interface{}{"amount": float64(4200), "currency": "USD"})
		return got, err, f.events
	}

	_, err, events := run(func(*ApprovalGuardOptions) {})
	var refusal *ApprovalGuardError
	if !errors.As(err, &refusal) || refusal.Status != "UNVERIFIED" || refusal.Reason != verify.EnrolledDeviceKeysRequiredReason {
		t.Fatalf("without the keys: %v", err)
	}
	if containsString(events, "tool") || containsString(events, "consume") {
		t.Fatalf("refused receipt reached %v", events)
	}

	got, err, events := run(func(o *ApprovalGuardOptions) {
		o.EnrolledDeviceKeys = []string{spki}
		o.Requirement = &verify.RequirementFloor{RequiredApprovals: 1, RequireEnrolledDevice: true}
	})
	if err != nil || got != "sent" || !containsString(events, "tool") {
		t.Fatalf("with the keys: %q %v %v", got, err, events)
	}
}

func TestGuardRefusesAnEmptyEnrolledDeviceKey(t *testing.T) {
	f := newGuardFixture(t)
	f.opts.EnrolledDeviceKeys = []string{"MFkw", ""}
	_, err := NewApprovalGuard(f.client, f.opts, func(context.Context, map[string]interface{}) (string, error) { return "", nil })
	if err == nil || err.Error() != "intyga: approval guard EnrolledDeviceKeys must be an array of non-empty base64 keys" {
		t.Fatalf("got %v", err)
	}
}
