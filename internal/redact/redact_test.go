package redact

import (
	"errors"
	"strings"
	"testing"

	"github.com/Anwesha33/pii-shield/internal/detect"
	"github.com/Anwesha33/pii-shield/internal/policy"
	"github.com/Anwesha33/pii-shield/internal/vault"
)

func TestRoundTripRestoresOriginal(t *testing.T) {
	in := "Email anwesha@example.com or call 9876543210 about order 5512."
	v := vault.New()

	res, err := NewDefault().Redact(in, v)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if strings.Contains(res.Text, "anwesha@example.com") || strings.Contains(res.Text, "9876543210") {
		t.Fatalf("sensitive value survived redaction: %q", res.Text)
	}
	if !strings.Contains(res.Text, "[[EMAIL_1]]") {
		t.Fatalf("expected an email token, got %q", res.Text)
	}
	// The order number carries no PII and must be left alone; over-redaction
	// destroys the prompt's meaning just as surely as under-redaction leaks.
	if !strings.Contains(res.Text, "5512") {
		t.Errorf("non-sensitive value was redacted: %q", res.Text)
	}

	if got := Rehydrate(res.Text, v); got != in {
		t.Errorf("round trip changed the text:\n got: %q\nwant: %q", got, in)
	}
}

func TestRepeatedValueGetsStableToken(t *testing.T) {
	in := "Forward anwesha@example.com the receipt, then cc anwesha@example.com again."
	v := vault.New()

	res, err := NewDefault().Redact(in, v)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if n := strings.Count(res.Text, "[[EMAIL_1]]"); n != 2 {
		t.Errorf("expected the same address to share one token twice, got %d occurrences in %q", n, res.Text)
	}
	if v.Len() != 1 {
		t.Errorf("expected 1 vault entry, got %d", v.Len())
	}
}

func TestOffsetsSurviveLengthChangingReplacements(t *testing.T) {
	// Three entities of very different lengths in one line. If replacement ran
	// forwards, the second and third spans would be rewritten at stale offsets
	// and the output would be corrupted.
	in := "a@b.co then 9876543210 then longer.address.here@example.co.in end"
	v := vault.New()

	res, err := NewDefault().Redact(in, v)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	for _, leaked := range []string{"a@b.co", "9876543210", "longer.address.here@example.co.in"} {
		if strings.Contains(res.Text, leaked) {
			t.Errorf("value %q survived: %q", leaked, res.Text)
		}
	}
	if !strings.HasPrefix(res.Text, "[[EMAIL_") || !strings.HasSuffix(res.Text, "end") {
		t.Errorf("structure damaged: %q", res.Text)
	}
	if got := Rehydrate(res.Text, v); got != in {
		t.Errorf("round trip failed:\n got: %q\nwant: %q", got, in)
	}
}

func TestBlockedEntityRejectsRequest(t *testing.T) {
	v := vault.New()
	_, err := NewDefault().Redact("use key sk-abcdefghijklmnop1234567890 please", v)

	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected BlockedError, got %v", err)
	}
	if blocked.Type != detect.APIKey {
		t.Errorf("expected API_KEY block, got %s", blocked.Type)
	}
	if v.Len() != 0 {
		t.Errorf("blocked request must not populate the vault, got %d entries", v.Len())
	}
}

func TestMaskIsIrreversibleButKeepsSuffix(t *testing.T) {
	v := vault.New()
	res, err := NewDefault().Redact("card 4111 1111 1111 1111 on file", v)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if !strings.Contains(res.Text, "****1111") {
		t.Fatalf("expected masked suffix, got %q", res.Text)
	}
	// Masked values are deliberately absent from the vault: rehydration must
	// not be able to bring them back.
	if got := Rehydrate(res.Text, v); strings.Contains(got, "4111 1111 1111 1111") {
		t.Error("masked card was restored on rehydrate; masking must be one-way")
	}
}

func TestUnknownTokensSurviveRehydration(t *testing.T) {
	v := vault.New()
	in := "see [[EMAIL_7]] for details"
	if got := Rehydrate(in, v); got != in {
		t.Errorf("hallucinated token should be left intact, got %q", got)
	}
}

func TestScanOutputFlagsNewEntities(t *testing.T) {
	v := vault.New()
	r := NewDefault()
	if _, err := r.Redact("contact anwesha@example.com", v); err != nil {
		t.Fatalf("redact: %v", err)
	}

	// A response echoing a value that was never in the request is a leak.
	leaked := ScanOutput("sure, I also found rahul@other.com in my notes", v)
	if len(leaked) == 0 {
		t.Fatal("expected the unseen address to be flagged")
	}
	// A response containing only values the caller already supplied is not.
	if got := ScanOutput("I emailed anwesha@example.com", v); len(got) != 0 {
		t.Errorf("value from the original request should not count as a leak, got %v", got)
	}
}

func TestAllowActionLeavesValueAlone(t *testing.T) {
	pol := policy.Default()
	pol.Rules[string(detect.Email)] = policy.Rule{Type: detect.Email, Action: policy.Allow}
	r := New(detect.NewEngineWith(pol.EnabledTypes()), pol)

	v := vault.New()
	res, err := r.Redact("mail anwesha@example.com", v)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if !strings.Contains(res.Text, "anwesha@example.com") {
		t.Errorf("allow action should pass the value through, got %q", res.Text)
	}
}
