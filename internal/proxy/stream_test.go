package proxy

import (
	"strings"
	"testing"

	"github.com/Anwesha33/pii-shield/internal/vault"
)

// feed pushes chunks through the rewriter and returns the concatenated output.
func feed(v *vault.Vault, chunks ...string) string {
	sw := newStreamRewriter(v)
	var b strings.Builder
	for _, c := range chunks {
		b.WriteString(sw.Write(c))
	}
	b.WriteString(sw.Flush())
	return b.String()
}

func TestStreamRehydratesTokenSplitAcrossChunks(t *testing.T) {
	v := vault.New()
	tok := v.Tokenize("EMAIL", "anwesha@example.com")
	if tok != "[[EMAIL_1]]" {
		t.Fatalf("unexpected token %q", tok)
	}

	// Every split point of the placeholder must produce identical output.
	full := "I sent it to [[EMAIL_1]] just now"
	want := "I sent it to anwesha@example.com just now"

	for i := 1; i < len(full); i++ {
		got := feed(v, full[:i], full[i:])
		if got != want {
			t.Fatalf("split at %d produced %q, want %q", i, got, want)
		}
	}
}

func TestStreamHandlesCharacterByCharacterDelivery(t *testing.T) {
	v := vault.New()
	v.Tokenize("PHONE_IN", "9876543210")

	full := "call [[PHONE_IN_1]] now"
	chunks := make([]string, 0, len(full))
	for _, r := range full {
		chunks = append(chunks, string(r))
	}
	if got, want := feed(v, chunks...), "call 9876543210 now"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestStreamDoesNotStallOnLiteralBrackets(t *testing.T) {
	// Text that opens with "[[" but never closes must still be emitted rather
	// than held back forever.
	v := vault.New()
	long := "[[" + strings.Repeat("x", maxTokenLen+20)
	got := feed(v, long)
	if got != long {
		t.Errorf("literal bracket text was not released intact:\n got %q\nwant %q", got, long)
	}
}

func TestStreamPassesThroughPlainText(t *testing.T) {
	v := vault.New()
	if got := feed(v, "hello ", "world"); got != "hello world" {
		t.Errorf("got %q", got)
	}
}
