package proxy

import (
	"strings"

	"github.com/Anwesha33/pii-shield/internal/redact"
	"github.com/Anwesha33/pii-shield/internal/vault"
)

// maxTokenLen bounds how many bytes a placeholder can occupy. Tokens look like
// [[PERSON_NAME_123]]; 64 bytes is comfortably above the longest entity name
// plus a five digit ordinal.
const maxTokenLen = 64

// streamRewriter re-hydrates redaction tokens in a response that arrives in
// pieces.
//
// This is the part of a streaming proxy that is easy to get wrong. The upstream
// splits its output on token boundaries that have nothing to do with ours, so a
// placeholder can straddle two chunks: one chunk ends with "[[EMA" and the next
// begins with "IL_1]]". Rewriting each chunk independently would emit the two
// halves untouched and the caller would see a broken placeholder instead of
// their own email address.
//
// The fix is to hold back any trailing text that could still turn out to be the
// start of a placeholder, and release it once the chunk that completes it
// arrives. Everything before that point is safe to emit immediately, so the
// stream keeps flowing and the caller sees no added latency beyond at most a
// partial token's worth of text.
type streamRewriter struct {
	v       *vault.Vault
	pending strings.Builder
}

func newStreamRewriter(v *vault.Vault) *streamRewriter {
	return &streamRewriter{v: v}
}

// Write accepts the next chunk of upstream content and returns the portion that
// is safe to forward now.
func (s *streamRewriter) Write(chunk string) string {
	s.pending.WriteString(chunk)
	buf := s.pending.String()

	// cut is the index from which text must be withheld because it might be an
	// incomplete placeholder.
	cut := len(buf)
	if i := strings.LastIndex(buf, "[["); i >= 0 && !strings.Contains(buf[i:], "]]") {
		// An unclosed "[[" is an open placeholder. Hold it, unless it has grown
		// past any legal token length, in which case it was never a placeholder
		// and holding it forever would stall the stream.
		if len(buf)-i <= maxTokenLen {
			cut = i
		}
	} else if strings.HasSuffix(buf, "[") {
		// A lone trailing "[" is the first half of a placeholder whose second
		// bracket has not arrived yet. Emitting it now would split the "[[" across
		// two flushes and the placeholder could never be recognised.
		cut = len(buf) - 1
	}

	out := redact.Rehydrate(buf[:cut], s.v)
	s.pending.Reset()
	s.pending.WriteString(buf[cut:])
	return out
}

// Flush returns whatever is still held back, at end of stream. Any unterminated
// placeholder is emitted as-is rather than dropped.
func (s *streamRewriter) Flush() string {
	out := redact.Rehydrate(s.pending.String(), s.v)
	s.pending.Reset()
	return out
}
