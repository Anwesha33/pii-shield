package detect

import (
	"regexp"
	"strings"
)

// regexDetector is the workhorse behind most entity classes. A bare pattern is
// rarely enough on its own, so it supports two refinements:
//
//   - validate: a check-digit or structural test run on the candidate. This is
//     what separates a real card number from any sixteen consecutive digits.
//   - context: keywords that must appear near the candidate. Used for entities
//     whose surface form carries no redundancy at all (a bank account number is
//     just digits), where the surrounding words are the only available signal.
type regexDetector struct {
	name       string
	typ        EntityType
	re         *regexp.Regexp
	confidence float64

	// validate, when non-nil, must return true for the candidate to be kept.
	validate func(string) bool

	// context, when non-empty, requires one of these lowercase keywords to
	// appear within contextWindow bytes on either side of the candidate.
	context []string
}

// contextWindow is how far on each side of a candidate we look for supporting
// keywords. Roughly one clause in either direction: wide enough to catch
// "account number is 123456789", narrow enough that an unrelated mention of
// "account" two sentences away does not license a match.
const contextWindow = 48

func (d *regexDetector) Name() string     { return d.name }
func (d *regexDetector) Type() EntityType { return d.typ }

func (d *regexDetector) Find(text string) []Match {
	idx := d.re.FindAllStringSubmatchIndex(text, -1)
	if idx == nil {
		return nil
	}
	lower := ""
	if len(d.context) > 0 {
		lower = strings.ToLower(text)
	}

	out := make([]Match, 0, len(idx))
	for _, loc := range idx {
		// Prefer capture group 1 when the pattern defines one: it lets a
		// pattern require surrounding punctuation without swallowing it into
		// the redacted span.
		start, end := loc[0], loc[1]
		if len(loc) >= 4 && loc[2] >= 0 {
			start, end = loc[2], loc[3]
		}
		val := text[start:end]

		if d.validate != nil && !d.validate(val) {
			continue
		}
		if len(d.context) > 0 && !hasContext(lower, start, end, d.context) {
			continue
		}
		out = append(out, Match{
			Type:       d.typ,
			Start:      start,
			End:        end,
			Value:      val,
			Confidence: d.confidence,
			Detector:   d.name,
		})
	}
	return out
}

// hasContext reports whether any keyword appears within contextWindow bytes of
// the span [start,end) in the already-lowercased text.
func hasContext(lowerText string, start, end int, keywords []string) bool {
	lo := start - contextWindow
	if lo < 0 {
		lo = 0
	}
	hi := end + contextWindow
	if hi > len(lowerText) {
		hi = len(lowerText)
	}
	window := lowerText[lo:hi]
	for _, kw := range keywords {
		if containsWord(window, kw) {
			return true
		}
	}
	return false
}

// containsWord reports whether kw appears in s delimited by non-alphanumeric
// characters.
//
// Plain substring matching is wrong here in a way that is easy to miss: the
// keyword "bank" occurs inside the UPI handle "okhdfcbank", so an unrelated
// payment address sitting within the context window was enough to license a
// bank-account match on a nearby placeholder number. Requiring word boundaries
// removes a whole class of these accidental activations.
func containsWord(s, kw string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], kw)
		if j < 0 {
			return false
		}
		start := i + j
		end := start + len(kw)
		if !isWordByte(s, start-1) && !isWordByte(s, end) {
			return true
		}
		i = start + 1
		if i >= len(s) {
			return false
		}
	}
}

// isWordByte reports whether the byte at index i is alphanumeric. Out-of-range
// indices count as non-word, so matches at either end of the window succeed.
func isWordByte(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// upiHandles is an explicit allow-list of payment-handle suffixes. A generic
// "word@word" pattern would swallow ordinary email addresses and social
// handles, so UPI is matched against known PSP handles instead.
var upiHandles = strings.Join([]string{
	"okhdfcbank", "oksbi", "okaxis", "okicici", "ybl", "ibl", "axl",
	"paytm", "upi", "apl", "airtel", "freecharge", "jupiteraxis", "fam",
}, "|")

// builtinDetectors returns the default detector set in priority order. Earlier
// entries win ties during overlap resolution, so the checksum-backed and more
// specific detectors are listed first.
func builtinDetectors() []Detector {
	return []Detector{
		&regexDetector{
			name: "jwt", typ: JWT, confidence: 0.99,
			// No trailing \b: a base64url signature may end in "-" or "_", which are
			// not word characters, so a word boundary would truncate the token and
			// leave the last character of the signature in the outbound prompt.
			re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		},
		&regexDetector{
			name: "api_key", typ: APIKey, confidence: 0.97,
			re: regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[baprs]-[0-9A-Za-z-]{10,})\b`),
		},
		&regexDetector{
			name: "credit_card_luhn", typ: CreditCard, confidence: 0.98,
			re:       regexp.MustCompile(`\b(?:\d{4}[ -]?){3}\d{1,7}\b`),
			validate: func(s string) bool { return validCard(digitsOnly(s)) },
		},
		&regexDetector{
			name: "aadhaar_verhoeff", typ: Aadhaar, confidence: 0.97,
			re:       regexp.MustCompile(`\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b`),
			validate: func(s string) bool { return !isRepeatedDigits(s) && verhoeff(digitsOnly(s)) },
		},
		&regexDetector{
			name: "pan", typ: PAN, confidence: 0.95,
			re: regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`),
		},
		&regexDetector{
			name: "ifsc", typ: IFSC, confidence: 0.95,
			re: regexp.MustCompile(`\b[A-Z]{4}0[A-Z0-9]{6}\b`),
		},
		&regexDetector{
			name: "email", typ: Email, confidence: 0.96,
			re: regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
		},
		&regexDetector{
			name: "upi", typ: UPI, confidence: 0.94,
			re: regexp.MustCompile(`\b[A-Za-z0-9._\-]{2,}@(?:` + upiHandles + `)\b`),
		},
		&regexDetector{
			name: "phone_in", typ: PhoneIN, confidence: 0.92,
			// The capture group spans the country code as well, so the whole
			// number is redacted as one unit rather than leaving "+91" behind.
			// A leading delimiter is matched (and excluded from the group)
			// because RE2 has no lookbehind and \b cannot anchor before "+".
			re: regexp.MustCompile(`(?:^|[\s(,:;=\-])((?:\+?91[ \-]?)?[6-9]\d{4}[ \-]?\d{5})\b`),
		},
		&regexDetector{
			name: "phone_us", typ: PhoneUS, confidence: 0.90,
			re: regexp.MustCompile(`(?:\+?1[ \-]?)?(\(?\d{3}\)?[ \-]\d{3}[ \-]\d{4})\b`),
		},
		&regexDetector{
			name: "passport_in", typ: PassportIN, confidence: 0.80,
			re:      regexp.MustCompile(`\b[A-PR-WY][0-9]{7}\b`),
			context: []string{"passport"},
		},
		&regexDetector{
			name: "ipv4", typ: IPAddress, confidence: 0.85,
			re:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			validate: validIPv4,
		},
		&regexDetector{
			name: "bank_account", typ: BankAccount, confidence: 0.70,
			re:       regexp.MustCompile(`\b\d{9,18}\b`),
			validate: func(s string) bool { return !isRepeatedDigits(s) },
			context:  []string{"account", "a/c", "acct", "bank", "beneficiary"},
		},
		&regexDetector{
			name: "person_name_cue", typ: PersonName, confidence: 0.60,
			// The case-insensitive flag is scoped to the cue phrase only. Applying it
			// to the whole pattern would make [A-Z] match lowercase letters, and the
			// name group would run on past the name into the rest of the sentence.
			re: regexp.MustCompile(`(?i:\b(?:my name is|i am|this is|regards,?|sincerely,?|customer name:?|name:))\s+([A-Z][a-z]{1,15}(?: [A-Z][a-z]{1,15}){0,2})\b`),
		},
	}
}

// validIPv4 rejects dotted quads with out-of-range octets, which the pattern
// alone would happily accept (999.999.999.999) and which are far more often
// version strings than addresses.
func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for i := 0; i < len(p); i++ {
			n = n*10 + int(p[i]-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}
