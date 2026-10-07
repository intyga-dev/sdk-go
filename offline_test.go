package intyga

// Focused tests for what the shared vectors do not cover: single use, the reconciliation buffer, path
// safety, key forms, the client's fallback gating, and reconciliation.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verify "github.com/intyga-dev/sdk-go/verify"
)

// offlineFixture is a bundle directory holding the vectors' signed bundle, plus options that collect
// signatures from alice's and bob's offline keys — a 2-of-2 for "db.restart".
type offlineFixture struct {
	V         *offlineVectors
	dir       string
	asOf      time.Time
	collected int32
}

func newOfflineFixture(t *testing.T) *offlineFixture {
	t.Helper()
	V := loadOfflineVectors(t)
	dir := t.TempDir()
	if err := SaveTrustBundle(dir, TrustBundleFiles{JWS: V.BundleJWS, GatewayJWK: V.GatewayJWK}); err != nil {
		t.Fatalf("SaveTrustBundle: %v", err)
	}
	return &offlineFixture{V: V, dir: dir, asOf: mustTime(t, "2026-10-06T12:00:00.123Z")}
}

func (f *offlineFixture) action() OfflineAction {
	return OfflineAction{
		Target:     "prod-db-cluster-01",
		ActionType: "db.restart",
		Display:    "Restart the primary database",
		Params:     map[string]interface{}{"cluster": "primary", "force": false},
	}
}

func (f *offlineFixture) options(t *testing.T) *OfflineApprovalOptions {
	return &OfflineApprovalOptions{
		BundleDir:    f.dir,
		RequesterDID: f.V.RequesterDID,
		AsOf:         f.asOf,
		Warn:         func(string) {},
		CollectSignatures: func(_ context.Context, ch *OfflineChallenge) ([]string, error) {
			atomic.AddInt32(&f.collected, 1)
			var out []string
			for _, person := range []string{"alice", "bob"} {
				k := f.V.key(t, person, "offline")
				alg := "ES256"
				out = append(out, EncodeSignatureEnvelope(verify.ApprovalWitness{
					SignerDID:       f.V.People[person].DID,
					SignerPublicKey: k.SPKI,
					Signature:       signES256(t, keyFromSeed(t, k.Seed), ch.CanonicalPayload),
					SigAlg:          &alg,
				}))
			}
			return out, nil
		},
	}
}

func TestFileRedemptionStoreIsSingleUse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".redeemed")
	store, err := NewFileRedemptionStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !store.Redeem("off_once") {
		t.Fatal("first redemption refused")
	}
	if store.Redeem("off_once") {
		t.Fatal("second redemption of the same nonce succeeded")
	}
	marker, err := os.ReadFile(filepath.Join(dir, "off_once.used"))
	if err != nil {
		t.Fatalf("marker not written: %v", err)
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`).Match(marker) {
		t.Errorf("marker content %q is not a toISOString timestamp", marker)
	}
	if runtime.GOOS != "windows" {
		assertMode(t, dir, 0o700)
		assertMode(t, filepath.Join(dir, "off_once.used"), 0o600)
	}
}

func TestFileRedemptionStoreRaceHasOneWinner(t *testing.T) {
	store, err := NewFileRedemptionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.Redeem("off_raced") {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d goroutines redeemed the same nonce", wins)
	}
}

func TestUnsafeNoncesAreRefused(t *testing.T) {
	root := t.TempDir()
	store, err := NewFileRedemptionStore(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	for _, nonce := range []string{"../escape", "a/b", "", strings.Repeat("a", 201), "bad nonce"} {
		if store.Redeem(nonce) {
			t.Errorf("Redeem(%q) succeeded", nonce)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "escape.used")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a traversal nonce wrote outside the store: %v", err)
	}

	f := newOfflineFixture(t)
	bundle, err := LoadTrustBundle(f.dir, f.asOf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateOfflineChallenge(OfflineChallengeInput{
		Bundle: bundle, Target: "t", ActionType: "db.restart", Display: "d", Nonce: strPtr("../escape"), AsOf: f.asOf,
	}); err == nil || !strings.Contains(err.Error(), "safe path segment") {
		t.Fatalf("unsafe nonce accepted: %v", err)
	}
	// A supplied empty nonce is refused, never replaced by a generated one.
	if _, err := CreateOfflineChallenge(OfflineChallengeInput{
		Bundle: bundle, Target: "t", ActionType: "db.restart", Display: "d", Nonce: strPtr(""), AsOf: f.asOf,
	}); err == nil || !strings.Contains(err.Error(), "safe path segment") {
		t.Fatalf("empty nonce accepted: %v", err)
	}

	// ClearPendingApproval must never name a path outside the buffer.
	victim := filepath.Join(root, "victim.json")
	if err := os.WriteFile(victim, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	ClearPendingApproval("../victim", PendingOptions{BundleDir: root, BufferDir: filepath.Join(root, "buffer")})
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("ClearPendingApproval removed a file outside the buffer: %v", err)
	}
}

func TestCreateOfflineChallengeDefaults(t *testing.T) {
	f := newOfflineFixture(t)
	bundle, err := LoadTrustBundle(f.dir, f.asOf)
	if err != nil {
		t.Fatal(err)
	}
	// A whole-second clock must still produce exactly three fractional digits: RFC3339Nano would
	// trim them, and the signed bytes would then differ from every other SDK's.
	asOf := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	in := OfflineChallengeInput{Bundle: bundle, Target: "t", ActionType: "db.restart", Display: "d", AsOf: asOf}
	a, err := CreateOfflineChallenge(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.ChallengedAt != "2026-10-06T12:00:00.000Z" || a.ExpiresAt != "2026-10-06T12:15:00.000Z" {
		t.Errorf("timestamps %s / %s", a.ChallengedAt, a.ExpiresAt)
	}
	uuid := regexp.MustCompile(`^off_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuid.MatchString(a.Nonce) {
		t.Errorf("default nonce %q is not off_<uuid v4>", a.Nonce)
	}
	b, err := CreateOfflineChallenge(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.Nonce == b.Nonce {
		t.Error("two challenges share a nonce")
	}
	if !strings.HasPrefix(a.Envelope, ChallengeEnvelopePrefix) || strings.Contains(a.Envelope, "=") {
		t.Errorf("envelope %q is not DIV1: + unpadded base64url", a.Envelope)
	}
	decoded, err := DecodeChallengeEnvelope("\n " + a.Envelope + "\t")
	if err != nil || decoded.CanonicalPayload != a.CanonicalPayload || decoded.VerificationCode != a.VerificationCode {
		t.Fatalf("round trip failed: %v", err)
	}
	// Sub-millisecond precision is dropped, exactly as a JavaScript Date would.
	in.AsOf = asOf.Add(1500 * time.Microsecond)
	c, err := CreateOfflineChallenge(in)
	if err != nil {
		t.Fatal(err)
	}
	if c.ChallengedAt != "2026-10-06T12:00:00.001Z" || c.ExpiresAt != "2026-10-06T12:15:00.001Z" {
		t.Errorf("timestamps %s / %s", c.ChallengedAt, c.ExpiresAt)
	}
}

func TestUseOfflineApprovalBuffersThenRedeems(t *testing.T) {
	f := newOfflineFixture(t)
	var warnings []string
	opts := f.options(t)
	opts.Warn = func(m string) { warnings = append(warnings, m) }
	r, err := UseOfflineApproval(context.Background(), f.action(), *opts)
	if err != nil {
		t.Fatalf("UseOfflineApproval: %v", err)
	}
	if len(r.Signers) != 2 || r.Signers[0] != "did:intyga:alice" || r.Signers[1] != "did:intyga:bob" {
		t.Errorf("signers %v", r.Signers)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "OFFLINE APPROVAL USED") || !strings.Contains(warnings[0], r.Nonce) {
		t.Errorf("expected one loud warning naming the nonce, got %q", warnings)
	}
	if _, err := os.Stat(filepath.Join(f.dir, ".redeemed", r.Nonce+".used")); err != nil {
		t.Errorf("nonce not redeemed on disk: %v", err)
	}
	record := filepath.Join(f.dir, ".pending", r.Nonce+".json")
	if runtime.GOOS != "windows" {
		assertMode(t, record, 0o600)
		assertMode(t, filepath.Join(f.dir, ".pending"), 0o700)
	}

	pending, err := PendingApprovals(PendingOptions{BundleDir: f.dir})
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %v, %v", pending, err)
	}
	p := pending[0]
	if p.Nonce != r.Nonce || p.Target != "prod-db-cluster-01" || p.ActionType != "db.restart" ||
		p.Display != "Restart the primary database" || p.DelegationNonce != "" ||
		p.Receipt.CanonicalPayload != r.Receipt.CanonicalPayload || len(p.Receipt.Signatures) != 2 {
		t.Errorf("pending record %+v", p)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", p.UsedAt); err != nil {
		t.Errorf("usedAt %q: %v", p.UsedAt, err)
	}
	// The buffered receipt still verifies offline, exactly as the gateway will re-verify it.
	bundle, _ := LoadTrustBundle(f.dir, f.asOf)
	check := verify.VerifyApprovalReceipt(p.Receipt, verify.Expected{
		Target: p.Target, ActionType: p.ActionType, Params: f.action().Params, Nonce: p.Nonce,
		Approvers: ApproverAnchor(bundle, []string{"did:intyga:alice", "did:intyga:bob"}, BundleAnchorOfflineIntent),
	}, verify.VerifyOptions{AllowOffline: true, AsOf: f.asOf})
	if !check.OK {
		t.Errorf("buffered receipt does not verify: %s", check.Reason)
	}
	// And never as an ordinary approval.
	if check := verify.VerifyApprovalReceipt(p.Receipt, verify.Expected{
		Target: p.Target, ActionType: p.ActionType, Params: f.action().Params, Nonce: p.Nonce,
		Approvers: ApproverAnchor(bundle, nil, BundleAnchorOfflineIntent),
	}, verify.VerifyOptions{AsOf: f.asOf}); check.OK {
		t.Error("an offline receipt verified without AllowOffline")
	}

	ClearPendingApproval(r.Nonce, PendingOptions{BundleDir: f.dir})
	if pending, _ := PendingApprovals(PendingOptions{BundleDir: f.dir}); len(pending) != 0 {
		t.Errorf("record not cleared: %v", pending)
	}
}

type refusingStore struct{}

func (refusingStore) Redeem(string) bool { return false }

func TestUseOfflineApprovalRefusesAnAlreadyRedeemedNonce(t *testing.T) {
	f := newOfflineFixture(t)
	opts := f.options(t)
	opts.Store = refusingStore{}
	_, err := UseOfflineApproval(context.Background(), f.action(), *opts)
	if err == nil || !strings.Contains(err.Error(), "already been redeemed") {
		t.Fatalf("expected a redemption refusal, got %v", err)
	}
	// The record buffered before redemption is withdrawn again: nothing was approved.
	if pending, _ := PendingApprovals(PendingOptions{BundleDir: f.dir}); len(pending) != 0 {
		t.Errorf("a refused approval left a pending record: %v", pending)
	}
}

func TestUseOfflineApprovalRefusals(t *testing.T) {
	f := newOfflineFixture(t)

	opts := f.options(t)
	opts.CollectSignatures = func(context.Context, *OfflineChallenge) ([]string, error) { return nil, nil }
	if _, err := UseOfflineApproval(context.Background(), f.action(), *opts); err == nil ||
		!strings.Contains(err.Error(), "no signatures were collected") {
		t.Errorf("empty collection: %v", err)
	}

	// A failed collection fails the approval with that error, and nothing is buffered or redeemed.
	cancelled := errors.New("operator cancelled")
	opts = f.options(t)
	opts.CollectSignatures = func(context.Context, *OfflineChallenge) ([]string, error) { return nil, cancelled }
	if _, err := UseOfflineApproval(context.Background(), f.action(), *opts); !errors.Is(err, cancelled) {
		t.Errorf("collection error: %v", err)
	}
	if pending, err := PendingApprovals(PendingOptions{BundleDir: f.dir}); len(pending) != 0 || err != nil {
		t.Errorf("a failed collection buffered %v (%v)", pending, err)
	}
	if redeemed, _ := os.ReadDir(filepath.Join(f.dir, ".redeemed")); len(redeemed) != 0 {
		t.Errorf("a failed collection redeemed %d nonce(s)", len(redeemed))
	}

	// A pasted null, array or stray-character envelope is discarded; the rest still count.
	opts = f.options(t)
	inner := opts.CollectSignatures
	opts.CollectSignatures = func(ctx context.Context, ch *OfflineChallenge) ([]string, error) {
		good, err := inner(ctx, ch)
		bad := []string{"SIG1:bnVsbA", "SIG1:W10", "SIG1:NDI", good[0][:20] + "\n" + good[0][20:]}
		return append(bad, good...), err
	}
	if r, err := UseOfflineApproval(context.Background(), f.action(), *opts); err != nil || len(r.Signers) != 2 {
		t.Errorf("garbled envelopes aborted the ceremony: %+v %v", r, err)
	}

	// No bundle at all fails closed, loudly.
	opts = f.options(t)
	opts.BundleDir = filepath.Join(t.TempDir(), "nothing-here")
	if _, err := UseOfflineApproval(context.Background(), f.action(), *opts); err == nil ||
		!strings.Contains(err.Error(), "no trust bundle at") {
		t.Errorf("missing bundle: %v", err)
	}

	// The age cap is inclusive of 30 days: a bundle 29 days old still works.
	opts = f.options(t)
	opts.AsOf = f.asOf.Add(29 * 24 * time.Hour)
	if _, err := UseOfflineApproval(context.Background(), f.action(), *opts); err != nil {
		t.Errorf("a bundle 29 days old should still be usable: %v", err)
	}
}

func TestEnvelopesAreStrictBase64URLObjects(t *testing.T) {
	f := newOfflineFixture(t)
	bundle, _ := LoadTrustBundle(f.dir, f.asOf)
	ch, err := CreateOfflineChallenge(OfflineChallengeInput{Bundle: bundle, Target: "t", ActionType: "db.restart", Display: "d", AsOf: f.asOf})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimPrefix(ch.Envelope, ChallengeEnvelopePrefix)
	// A BOM is JavaScript whitespace and is trimmed; NEL is not, so it is refused as a prefix.
	if _, err := DecodeChallengeEnvelope("\ufeff" + ch.Envelope); err != nil {
		t.Errorf("BOM-prefixed: %v", err)
	}
	if _, err := DecodeChallengeEnvelope("\u0085" + ch.Envelope); err == nil {
		t.Error("NEL-prefixed accepted")
	}
	// Shapes are checked before bytes: each of these is canonical JSON that re-serializes to itself.
	payload := func(mutate func(map[string]interface{})) string {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(ch.CanonicalPayload), &m); err != nil {
			t.Fatal(err)
		}
		mutate(m)
		text, err := verify.StableStringify(m)
		if err != nil {
			t.Fatal(err)
		}
		return ChallengeEnvelopePrefix + base64.RawURLEncoding.EncodeToString([]byte(text))
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"target number":     func(m map[string]interface{}) { m["target"] = 5.0 },
		"blank target":      func(m map[string]interface{}) { m["target"] = "\u3000" },
		"display missing":   func(m map[string]interface{}) { delete(m, "display") },
		"nonce null":        func(m map[string]interface{}) { m["nonce"] = nil },
		"params array":      func(m map[string]interface{}) { m["params"] = []interface{}{} },
		"params null":       func(m map[string]interface{}) { m["params"] = nil },
		"requester no did":  func(m map[string]interface{}) { m["requester"] = map[string]interface{}{"attestation": nil} },
		"requirement array": func(m map[string]interface{}) { m["requirement"] = []interface{}{} },
	} {
		if _, err := DecodeChallengeEnvelope(payload(mutate)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	refused := []string{
		ChallengeEnvelopePrefix + body[:10] + "\n" + body[10:], // Go's decoder would skip CR/LF
		ChallengeEnvelopePrefix + body[:10] + " " + body[10:],
		ChallengeEnvelopePrefix + strings.NewReplacer("-", "+", "_", "/").Replace(body) + "+/", // standard alphabet
		ChallengeEnvelopePrefix + body + "===",
		ChallengeEnvelopePrefix + "MQ",     // 1
		ChallengeEnvelopePrefix + "IngiIA", // "x"
	}
	for _, env := range refused {
		if _, err := DecodeChallengeEnvelope(env); err == nil {
			t.Errorf("accepted %q", env)
		}
	}
	if _, err := DecodeChallengeEnvelope(ch.Envelope + "=="); err != nil {
		t.Errorf("padding is optional, not refused: %v", err)
	}
	for _, env := range []string{"SIG1:MQ", "SIG1:IngiIA", "SIG1:dHJ1ZQ"} { // 1, "x", true
		if _, err := DecodeSignatureEnvelope(env); err == nil || !strings.Contains(err.Error(), "not a JSON object") {
			t.Errorf("%s: %v", env, err)
		}
	}
	// alg present but empty is refused like any non-string alg.
	if _, err := DecodeSignatureEnvelope(SignatureEnvelopePrefix + base64.RawURLEncoding.EncodeToString(
		[]byte(`{"did":"did:x:a","key":"k","sig":"s","alg":""}`))); err == nil {
		t.Error("empty alg accepted")
	}
}

func TestBlankTargetIsRefused(t *testing.T) {
	f := newOfflineFixture(t)
	bundle, _ := LoadTrustBundle(f.dir, f.asOf)
	for _, target := range []string{"", " ", "\t\n", "\u00a0\u3000", "\ufeff"} {
		if _, err := CreateOfflineChallenge(OfflineChallengeInput{Bundle: bundle, Target: target, ActionType: "db.restart", Display: "d", AsOf: f.asOf}); err == nil ||
			!strings.Contains(err.Error(), "target is required") {
			t.Errorf("target %q: %v", target, err)
		}
	}
	// U+0085 is not JavaScript whitespace, so a target of only NEL is not blank.
	if _, err := CreateOfflineChallenge(OfflineChallengeInput{Bundle: bundle, Target: "\u0085", ActionType: "db.restart", Display: "d", AsOf: f.asOf}); err != nil {
		t.Errorf("NEL target: %v", err)
	}
	// And a blank-target UseOfflineApproval collects nothing.
	opts := f.options(t)
	action := f.action()
	action.Target = "  "
	if _, err := UseOfflineApproval(context.Background(), action, *opts); err == nil || f.collected != 0 {
		t.Errorf("blank target: %v (collected %d)", err, f.collected)
	}
}

func TestJSTrimMatchesStringPrototypeTrim(t *testing.T) {
	// ECMAScript WhiteSpace + LineTerminator: TAB VT FF SP NBSP ZWNBSP(BOM) every Zs, LF CR LS PS.
	for _, ws := range []string{"\t", "\v", "\f", " ", "\u00a0", "\ufeff", "\u1680", "\u2000", "\u200a",
		"\u202f", "\u205f", "\u3000", "\n", "\r", "\u2028", "\u2029"} {
		if got := jsTrim(ws + "x" + ws); got != "x" {
			t.Errorf("%U not trimmed: %q", []rune(ws)[0], got)
		}
	}
	// Not whitespace in JavaScript, though Go's unicode.IsSpace says U+0085 is.
	for _, keep := range []string{"\u0085", "\u200b", "\u180e"} {
		if got := jsTrim(keep + "x"); got != keep+"x" {
			t.Errorf("%U trimmed: %q", []rune(keep)[0], got)
		}
	}
}

func TestPolicyIntegersAreArchitectureIndependent(t *testing.T) {
	// A quorum above 2^31 is a valid (unmeetable) integer on every architecture: the bundle is
	// accepted and the action refused, rather than the value wrapping on a 32-bit build.
	huge := PolicyRule{ActionPattern: "*", RequiredApprovals: 1 << 40, ApproverDids: []string{"did:x:a"}}
	if err := ValidateExactApprovalPolicy([]PolicyRule{huge}); err != nil {
		t.Errorf("2^40 refused: %v", err)
	}
	unsafe := huge
	unsafe.RequiredApprovals = 1 << 53
	if err := ValidateExactApprovalPolicy([]PolicyRule{unsafe}); err == nil {
		t.Error("2^53 accepted")
	}
	f := newOfflineFixture(t)
	bundle, _ := LoadTrustBundle(f.dir, f.asOf)
	bundle.Policy[0].RequiredApprovals = 1 << 40
	for i := range bundle.Policy[1:] {
		bundle.Policy[i+1].RequiredApprovals = 1 << 40
	}
	if _, ok := RequirementFor(bundle, "db.restart", "d"); ok {
		t.Error("an unmeetable quorum resolved")
	}
}

func TestStrictTimestamps(t *testing.T) {
	for _, bad := range []string{
		"2026-10-06", "2026-10-06T12:00:00", "2026-10-06t12:00:00Z", "2026-02-30T12:00:00Z",
		"2026-10-06T24:00:00Z", "2026-10-06T12:00:60Z", "2026-10-06T12:00:00,5Z",
		"2026-10-06T12:00:00.1234567891Z", "2026-10-06T12:00:00+24:00", "2026-10-06T12:00:00+05:60", "",
	} {
		if _, ok := parseTimestampMillis(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	for good, ms := range map[string]int64{
		"2026-10-06T12:00:00Z":           1791288000000,
		"2026-10-06T12:00:00.123Z":       1791288000123,
		"2026-10-06T14:00:00.1239+02:00": 1791288000123,
	} {
		if got, ok := parseTimestampMillis(good); !ok || got != ms {
			t.Errorf("%s: %d %v, want %d", good, got, ok, ms)
		}
	}
}

func TestPendingApprovalsReportsUnreadableRecords(t *testing.T) {
	dir := t.TempDir()
	good := PendingApproval{Nonce: "off_good", Target: "t", ActionType: "a", Display: "d", UsedAt: "2026-10-06T12:00:00.000Z"}
	data, _ := json.Marshal(good)
	if err := os.WriteFile(filepath.Join(dir, "off_good.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "off_bad.json"), []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := PendingApprovals(PendingOptions{BufferDir: dir})
	if len(records) != 1 || records[0].Nonce != "off_good" {
		t.Errorf("readable records were dropped: %v", records)
	}
	if err == nil || !strings.Contains(err.Error(), "off_bad.json") {
		t.Errorf("unreadable record not reported: %v", err)
	}
	if records, err := PendingApprovals(PendingOptions{BundleDir: filepath.Join(dir, "absent")}); err != nil || len(records) != 0 {
		t.Errorf("a missing buffer should read as empty: %v %v", records, err)
	}
}

func TestSignChallengeEnvelopeKeyForms(t *testing.T) {
	f := newOfflineFixture(t)
	bundle, _ := LoadTrustBundle(f.dir, f.asOf)
	ch, err := CreateOfflineChallenge(OfflineChallengeInput{
		Bundle: bundle, Target: "t", ActionType: "db.restart", Display: "d", AsOf: f.asOf,
		Requester: verify.RequesterIdentity{DID: f.V.RequesterDID},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := keyFromSeed(t, f.V.key(t, "alice", "offline").Seed)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	// SEC1 is what `openssl ecparam -genkey` writes; the contract requires it alongside PKCS#8.
	sec1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})
	forms := map[string]interface{}{
		"ecdsa":           key,
		"pkcs8 pem":       string(pkcs8PEM),
		"pkcs8 pem bytes": pkcs8PEM,
		"pkcs8 der":       pkcs8,
		"sec1 pem":        string(sec1PEM),
		"sec1 pem bytes":  sec1PEM,
	}
	for name, form := range forms {
		signed, err := SignChallengeEnvelope(ch.Envelope, SignChallengeOptions{PrivateKey: form, SignerDID: "did:intyga:alice", AsOf: f.asOf})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		w, err := DecodeSignatureEnvelope(signed.Envelope)
		if err != nil || w.SignerPublicKey != f.V.key(t, "alice", "offline").SPKI {
			t.Errorf("%s: witness %+v, %v", name, w, err)
		}
		receipt := AssembleOfflineReceipt(ch, []verify.ApprovalWitness{w})
		res := verify.VerifyApprovalReceipt(receipt, verify.Expected{
			Target: "t", ActionType: "db.restart", Params: map[string]interface{}{}, Nonce: ch.Nonce,
			Approvers: ApproverAnchor(bundle, nil, BundleAnchorOfflineIntent),
		}, verify.VerifyOptions{AllowOffline: true, AsOf: f.asOf})
		// db.restart is 2-of-N, so one signature is short — but it must be counted as alice's.
		if res.OK || !strings.Contains(res.Reason, "1 of 2") {
			t.Errorf("%s: %+v", name, res)
		}
	}

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, bad := range map[string]interface{}{"p384": p384, "rsa": rsaKey, "nil": nil, "garbage": []byte("not a key")} {
		if _, err := SignChallengeEnvelope(ch.Envelope, SignChallengeOptions{PrivateKey: bad, SignerDID: "did:intyga:alice", AsOf: f.asOf}); err == nil {
			t.Errorf("%s key accepted", name)
		}
	}
	if _, err := SignChallengeEnvelope(ch.Envelope, SignChallengeOptions{PrivateKey: key, SignerDID: "alice", AsOf: f.asOf}); err == nil ||
		!strings.Contains(err.Error(), "must be a DID") {
		t.Errorf("non-DID signer: %v", err)
	}
}

func TestSignatureEnvelopeIsByteIdenticalToJSONStringify(t *testing.T) {
	alg := "ES256"
	// encoding/json would write <, >, & and  ; JSON.stringify writes them raw.
	env := EncodeSignatureEnvelope(verify.ApprovalWitness{
		SignerDID: "did:x:<a&b> \"q\"", SignerPublicKey: "k+/=", Signature: "s", SigAlg: &alg,
	})
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(env, SignatureEnvelopePrefix))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"did\":\"did:x:<a&b> \\\"q\\\"\",\"key\":\"k+/=\",\"sig\":\"s\",\"alg\":\"ES256\"}"
	if string(raw) != want {
		t.Fatalf("got  %s\nwant %s", raw, want)
	}
	// A missing alg is written as ES256, and read back as ES256 when absent.
	noAlg := EncodeSignatureEnvelope(verify.ApprovalWitness{SignerDID: "did:x:a", SignerPublicKey: "k", Signature: "s"})
	w, err := DecodeSignatureEnvelope(noAlg)
	if err != nil || w.SigAlg == nil || *w.SigAlg != "ES256" {
		t.Fatalf("alg default: %+v %v", w, err)
	}
}

func TestTrustBundleSaveAndLoad(t *testing.T) {
	f := newOfflineFixture(t)
	if runtime.GOOS != "windows" {
		assertMode(t, f.dir, 0o700)
		assertMode(t, filepath.Join(f.dir, "trust-bundle.jws"), 0o600)
		assertMode(t, filepath.Join(f.dir, "gateway-key.jwk.json"), 0o600)
	}
	jwk, err := os.ReadFile(filepath.Join(f.dir, "gateway-key.jwk.json"))
	if err != nil || !json.Valid(jwk) || !strings.HasSuffix(string(jwk), "}\n") {
		t.Errorf("gateway key file %q", jwk)
	}
	if _, err := LoadTrustBundle(f.dir, f.asOf); err != nil {
		t.Fatalf("LoadTrustBundle: %v", err)
	}
	if _, err := LoadTrustBundle(f.dir, f.asOf.Add(31*24*time.Hour)); err == nil {
		t.Error("a 32-day-old bundle loaded")
	}
	if err := os.Remove(filepath.Join(f.dir, "gateway-key.jwk.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustBundle(f.dir, f.asOf); err == nil || !strings.Contains(err.Error(), "no pinned gateway key") {
		t.Errorf("missing key: %v", err)
	}
	// The pinned key is the only trusted signer, and it must be RSA: RS256 is the only algorithm.
	ec := []byte(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`)
	if _, err := VerifyTrustBundle(f.V.BundleJWS, ec, f.asOf); err == nil || !strings.Contains(err.Error(), "must be an RSA JWK") {
		t.Errorf("non-RSA pinned key: %v", err)
	}
}

func TestApproverAnchorKeepsOfflineKeysOutOfOrdinaryAnchors(t *testing.T) {
	f := newOfflineFixture(t)
	bundle, _ := LoadTrustBundle(f.dir, f.asOf)
	offline := f.V.key(t, "alice", "offline").SPKI
	for _, k := range ApproverAnchor(bundle, nil, BundleAnchorOrdinary).ResolveKeys("did:intyga:alice") {
		if k == offline {
			t.Fatal("an ordinary anchor admitted an offline signing key")
		}
	}
	// An empty (non-nil) limit narrows to nobody; nil means everybody.
	if dids := ApproverAnchor(bundle, []string{}, BundleAnchorOrdinary).DIDs; len(dids) != 0 {
		t.Errorf("empty limit admitted %v", dids)
	}
}

// ── the fallback is reachable ONLY when the gateway could not be asked ────────────────────────────

func requireApprovalOpts(f *offlineFixture, t *testing.T, offline bool) RequireApprovalOptions {
	a := f.action()
	opts := RequireApprovalOptions{
		AuthorizeOptions: AuthorizeOptions{Target: a.Target, ActionType: a.ActionType, Params: a.Params},
		Interval:         5 * time.Millisecond,
		Timeout:          10 * time.Second,
	}
	if offline {
		opts.Offline = f.options(t)
	}
	return opts
}

func TestRequireApprovalFallsBackWhenTheGatewayIsUnreachable(t *testing.T) {
	f := newOfflineFixture(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens there now: a connection failure

	client := mustClient(t, ClientOptions{GatewayURL: url, Token: "t"})
	res, err := client.RequireApproval(context.Background(), f.action().Display, requireApprovalOpts(f, t, true))
	if err != nil {
		t.Fatalf("RequireApproval: %v", err)
	}
	if res.Status != StatusOfflineApproved || res.Status == StatusApproved {
		t.Fatalf("status %s, want OFFLINE_APPROVED", res.Status)
	}
	if res.Receipt == nil || res.Nonce == "" || !strings.HasPrefix(res.Nonce, "off_") {
		t.Fatalf("result %+v", res)
	}

	// Without the per-call opt-in there is no fallback, ever, and the transport error is returned.
	f.collected = 0
	if _, err := client.RequireApproval(context.Background(), f.action().Display, requireApprovalOpts(f, t, false)); err == nil {
		t.Fatal("an unreachable gateway returned no error without offline options")
	}
	if f.collected != 0 {
		t.Fatal("signatures were collected without offline options")
	}
}

func TestRequireApprovalFallsBackOn5xx(t *testing.T) {
	f := newOfflineFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()
	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	res, err := client.RequireApproval(context.Background(), f.action().Display, requireApprovalOpts(f, t, true))
	if err != nil || res.Status != StatusOfflineApproved {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestRequireApprovalNeverFallsBackOnARefusal(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409, 429, 307} {
		status := status
		f := newOfflineFixture(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if status == 307 {
				w.Header().Set("location", "https://elsewhere.invalid/")
			}
			w.WriteHeader(status)
		}))
		client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
		_, err := client.RequireApproval(context.Background(), f.action().Display, requireApprovalOpts(f, t, true))
		srv.Close()
		var refused *GatewayRefusedError
		if !errors.As(err, &refused) || refused.StatusCode != status {
			t.Errorf("%d: expected a GatewayRefusedError, got %v", status, err)
		}
		if f.collected != 0 {
			t.Errorf("%d: a refusal was answered with an offline approval", status)
		}
	}
}

func TestRequireApprovalNeverFallsBackOnDeniedOrExpired(t *testing.T) {
	for _, verdict := range []ApprovalStatus{StatusDenied, StatusExpired} {
		verdict := verdict
		f := newOfflineFixture(t)
		mux := http.NewServeMux()
		mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]interface{}{"nonce": "n1", "status": "PENDING"})
		})
		mux.HandleFunc("/authorize/n1", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]interface{}{"status": string(verdict)})
		})
		srv := httptest.NewServer(mux)
		client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
		res, err := client.RequireApproval(context.Background(), f.action().Display, requireApprovalOpts(f, t, true))
		srv.Close()
		if err != nil || res.Status != verdict {
			t.Errorf("%s: got %+v, %v", verdict, res, err)
		}
		if f.collected != 0 {
			t.Errorf("%s: a human's answer was overridden offline", verdict)
		}
		if pending, _ := PendingApprovals(PendingOptions{BundleDir: f.dir}); len(pending) != 0 {
			t.Errorf("%s: something was buffered", verdict)
		}
	}
}

func TestRequireApprovalPollingFailures(t *testing.T) {
	cases := []struct {
		status  int
		offline bool
	}{{503, true}, {500, true}, {404, false}, {403, false}}
	for _, c := range cases {
		c := c
		f := newOfflineFixture(t)
		mux := http.NewServeMux()
		mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]interface{}{"nonce": "n1", "status": "PENDING"})
		})
		mux.HandleFunc("/authorize/n1", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
		})
		srv := httptest.NewServer(mux)
		client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
		res, err := client.RequireApproval(context.Background(), f.action().Display, requireApprovalOpts(f, t, true))
		srv.Close()
		if c.offline {
			if err != nil || res.Status != StatusOfflineApproved {
				t.Errorf("%d: got %+v, %v", c.status, res, err)
			}
			continue
		}
		var refused *GatewayRefusedError
		if !errors.As(err, &refused) || f.collected != 0 {
			t.Errorf("%d: repeated refusals were answered offline (%v)", c.status, err)
		}
	}
}

func TestRequireApprovalPollingStreakWithARefusalNeverFallsBack(t *testing.T) {
	// [404, 503, 503, 503, 503]: the gateway answered once, so the streak is not an outage — the 404
	// is returned, even though the fifth failure is a 5xx.
	f := newOfflineFixture(t)
	var polls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"nonce": "n1", "status": "PENDING"})
	})
	mux.HandleFunc("/authorize/n1", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&polls, 1) == 1 {
			http.Error(w, "no such challenge", http.StatusNotFound)
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	_, err := client.RequireApproval(context.Background(), f.action().Display, requireApprovalOpts(f, t, true))
	var refused *GatewayRefusedError
	if !errors.As(err, &refused) || refused.StatusCode != http.StatusNotFound {
		t.Fatalf("expected the 404, got %v", err)
	}
	if f.collected != 0 || polls != maxPollErrors {
		t.Fatalf("collected=%d polls=%d", f.collected, polls)
	}

	// A successful poll resets the streak: [404, PENDING, 503 ×5] falls back.
	f = newOfflineFixture(t)
	polls = 0
	mux = http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"nonce": "n1", "status": "PENDING"})
	})
	mux.HandleFunc("/authorize/n1", func(w http.ResponseWriter, r *http.Request) {
		switch atomic.AddInt32(&polls, 1) {
		case 1:
			http.Error(w, "no such challenge", http.StatusNotFound)
		case 2:
			writeJSON(w, map[string]interface{}{"status": "PENDING"})
		default:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}
	})
	srv2 := httptest.NewServer(mux)
	defer srv2.Close()
	client = mustClient(t, ClientOptions{GatewayURL: srv2.URL, Token: "t"})
	res, err := client.RequireApproval(context.Background(), f.action().Display, requireApprovalOpts(f, t, true))
	if err != nil || res.Status != StatusOfflineApproved {
		t.Fatalf("after a reset streak: %+v %v", res, err)
	}
}

// roundTripFunc lets a test decide each request's transport outcome.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWithoutTheOptInTheCallerGetsTypedErrors(t *testing.T) {
	f := newOfflineFixture(t)
	opts := requireApprovalOpts(f, t, false)

	// Transport failure raising the challenge.
	down := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})}
	client := mustClient(t, ClientOptions{GatewayURL: "https://gw.invalid", Token: "t", HTTPClient: down})
	_, err := client.RequireApproval(context.Background(), "d", opts)
	var unreachable *GatewayUnreachableError
	if !errors.As(err, &unreachable) {
		t.Errorf("transport failure: %T %v", err, err)
	}

	// A 5xx raising the challenge.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()
	client = mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	_, err = client.RequireApproval(context.Background(), "d", opts)
	var refused *GatewayRefusedError
	if !errors.As(err, &refused) || refused.StatusCode != http.StatusBadGateway {
		t.Errorf("5xx: %T %v", err, err)
	}

	// The gateway goes away mid-wait: the polling error wraps the typed one.
	var calls int32
	flaky := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return &http.Response{
				StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"nonce":"n1","status":"PENDING"}`)), Request: r,
			}, nil
		}
		return nil, errors.New("connection reset")
	})}
	client = mustClient(t, ClientOptions{GatewayURL: "https://gw.invalid", Token: "t", HTTPClient: flaky})
	_, err = client.RequireApproval(context.Background(), "d", opts)
	if !errors.As(err, &unreachable) || !strings.Contains(err.Error(), "polling failed") {
		t.Errorf("polling transport failure: %T %v", err, err)
	}
	if f.collected != 0 {
		t.Error("signatures were collected without the opt-in")
	}
}

func TestRequireApprovalNeverFallsBackForAgentContinuityOrLocalErrors(t *testing.T) {
	f := newOfflineFixture(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	client := mustClient(t, ClientOptions{GatewayURL: url, Token: "t"})

	opts := requireApprovalOpts(f, t, true)
	opts.AgentContext = map[string]interface{}{"configDigest": "x"}
	if _, err := client.RequireApproval(context.Background(), f.action().Display, opts); err == nil ||
		!strings.Contains(err.Error(), "agent continuity") {
		t.Errorf("agent continuity: %v", err)
	}

	// A missing Target is a local error, never "the gateway could not be asked".
	opts = requireApprovalOpts(f, t, true)
	opts.Target = " "
	if _, err := client.RequireApproval(context.Background(), f.action().Display, opts); err == nil ||
		!strings.Contains(err.Error(), "Target is required") {
		t.Errorf("missing target: %v", err)
	}

	// So is a client with no credentials.
	bare := mustClient(t, ClientOptions{GatewayURL: url})
	if _, err := bare.RequireApproval(context.Background(), f.action().Display, requireApprovalOpts(f, t, true)); err == nil {
		t.Error("a client without credentials succeeded")
	}

	// And a 2xx whose body is not JSON: the gateway answered.
	garbled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>maintenance</html>"))
	}))
	defer garbled.Close()
	gc := mustClient(t, ClientOptions{GatewayURL: garbled.URL, Token: "t"})
	if _, err := gc.RequireApproval(context.Background(), f.action().Display, requireApprovalOpts(f, t, true)); err == nil {
		t.Error("an unreadable 2xx body succeeded")
	}
	if f.collected != 0 {
		t.Error("signatures were collected")
	}
}

// ── reconciliation ────────────────────────────────────────────────────────────────────────────────

func TestReconcileClearsOnlyAcknowledgedRecords(t *testing.T) {
	buffer := t.TempDir()
	for _, nonce := range []string{"n-ack", "n-refused", "n-down"} {
		record := PendingApproval{
			Nonce: nonce, Target: "t", ActionType: "a", Display: "d", UsedAt: "2026-10-06T12:00:00.000Z",
			Receipt: verify.ApprovalReceipt{CanonicalPayload: "{}", ActionDescription: "d", Params: map[string]interface{}{}},
		}
		if nonce == "n-ack" {
			record.DelegationNonce = "dlg-1"
		}
		data, _ := json.Marshal(record)
		if err := os.WriteFile(filepath.Join(buffer, nonce+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(buffer, "n-corrupt.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	var bodies sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/offline-approval/reconcile" || r.Method != http.MethodPost || r.Header.Get("authorization") != "Bearer t" {
			http.Error(w, "unexpected request", http.StatusTeapot)
			return
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		nonce, _ := body["nonce"].(string)
		bodies.Store(nonce, body)
		switch nonce {
		case "n-ack":
			writeJSON(w, map[string]interface{}{"ok": true})
		case "n-refused":
			http.Error(w, "already reconciled", http.StatusConflict)
		default:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	res, err := client.ReconcileOfflineApprovals(context.Background(), PendingOptions{BundleDir: "/unused", BufferDir: buffer})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reported != 1 || res.Failed != 3 {
		t.Fatalf("result %+v", res)
	}
	joined := strings.Join(res.Reasons, "\n")
	for _, want := range []string{"n-refused: 409 already reconciled", "n-down: 503 unavailable", "n-corrupt.json"} {
		if !strings.Contains(joined, want) {
			t.Errorf("reasons %q lack %q", res.Reasons, want)
		}
	}
	if _, err := os.Stat(filepath.Join(buffer, "n-ack.json")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the acknowledged record was not cleared")
	}
	for _, kept := range []string{"n-refused.json", "n-down.json", "n-corrupt.json"} {
		if _, err := os.Stat(filepath.Join(buffer, kept)); err != nil {
			t.Errorf("%s was cleared without an acknowledgement", kept)
		}
	}
	ack, _ := bodies.Load("n-ack")
	body := ack.(map[string]interface{})
	for _, field := range []string{"nonce", "usedAt", "target", "actionType", "display", "receipt", "delegationNonce"} {
		if _, ok := body[field]; !ok {
			t.Errorf("reconcile body lacks %s: %v", field, body)
		}
	}
	// An absent delegationNonce is omitted, never sent as null: the gateway refuses null.
	refused, _ := bodies.Load("n-refused")
	if _, ok := refused.(map[string]interface{})["delegationNonce"]; ok {
		t.Error("an absent delegationNonce was sent")
	}

	// A network failure clears nothing either.
	srv.Close()
	res, err = client.ReconcileOfflineApprovals(context.Background(), PendingOptions{BufferDir: buffer})
	if err != nil || res.Reported != 0 || res.Failed != 3 {
		t.Fatalf("offline reconcile: %+v %v", res, err)
	}

	// A misconfigured client fails up front rather than once per record.
	bare := mustClient(t, ClientOptions{GatewayURL: "https://gw.invalid"})
	if _, err := bare.ReconcileOfflineApprovals(context.Background(), PendingOptions{BufferDir: buffer}); err == nil {
		t.Error("a client without credentials reconciled")
	}
}

func strPtr(s string) *string { return &s }

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s has mode %o, want %o", path, got, want)
	}
}
