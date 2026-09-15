package detect

import "testing"

// findTypes runs the full engine and reports which entity types were found,
// which is what most of these cases actually care about.
func findTypes(t *testing.T, text string) map[EntityType][]string {
	t.Helper()
	got := make(map[EntityType][]string)
	for _, m := range NewEngine().Find(text) {
		got[m.Type] = append(got[m.Type], m.Value)
	}
	return got
}

func TestDetectorsFindExpectedEntities(t *testing.T) {
	cases := []struct {
		name string
		text string
		want EntityType
		val  string
	}{
		{"email", "ping me at anwesha.y@example.com ok", Email, "anwesha.y@example.com"},
		{"indian mobile", "call 9876543210 tomorrow", PhoneIN, "9876543210"},
		{"indian mobile with cc", "call +91 9876543210", PhoneIN, "+91 9876543210"},
		{"us phone", "reach 415-555-0134 anytime", PhoneUS, "415-555-0134"},
		{"aadhaar", "aadhaar 2345 6789 0124 attached", Aadhaar, "2345 6789 0124"},
		{"pan", "PAN ABCDE1234F filed", PAN, "ABCDE1234F"},
		{"card", "card 4111 1111 1111 1111 expiring", CreditCard, "4111 1111 1111 1111"},
		{"ifsc", "branch HDFC0001234 mumbai", IFSC, "HDFC0001234"},
		{"upi", "send to anwesha@okhdfcbank now", UPI, "anwesha@okhdfcbank"},
		{"ipv4", "server at 192.168.10.4 down", IPAddress, "192.168.10.4"},
		{"jwt", "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", JWT, ""},
		{"openai key", "key sk-abcdefghijklmnop1234567890 here", APIKey, "sk-abcdefghijklmnop1234567890"},
		{"aws key", "AKIAIOSFODNN7EXAMPLE rotated", APIKey, "AKIAIOSFODNN7EXAMPLE"},
		{"passport with context", "passport J8369854 issued", PassportIN, "J8369854"},
		{"bank account with context", "credit to account 123456789012 please", BankAccount, "123456789012"},
		{"name cue", "Hi, my name is Anwesha Yadav and I need help", PersonName, "Anwesha Yadav"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := findTypes(t, tc.text)
			vals, ok := got[tc.want]
			if !ok {
				t.Fatalf("expected %s in %q, got %v", tc.want, tc.text, got)
			}
			if tc.val != "" && vals[0] != tc.val {
				t.Errorf("expected value %q, got %q", tc.val, vals[0])
			}
		})
	}
}

// TestFalsePositives covers the inputs that a naive pattern set gets wrong.
// These are the cases that decide whether the proxy is usable in production:
// over-redaction silently destroys legitimate prompts.
func TestFalsePositives(t *testing.T) {
	cases := []struct {
		name string
		text string
		not  EntityType
	}{
		{"order id is not a card", "order 1234567890123456 shipped", CreditCard},
		{"random 12 digits is not aadhaar", "reference 111111111111 logged", Aadhaar},
		{"version string is not an ip", "upgraded to 999.999.999.999 build", IPAddress},
		{"bare digits without context are not an account", "quantity 123456789012 units", BankAccount},
		{"passport pattern without context", "sku J8369854 restocked", PassportIN},
		{"email is not a upi handle", "mail ops@paytm.com for help", UPI},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if vals, found := findTypes(t, tc.text)[tc.not]; found {
				t.Errorf("false positive: %s matched %v in %q", tc.not, vals, tc.text)
			}
		})
	}
}

// TestOverlapResolution pins the longest-match-wins rule, the behaviour most
// likely to regress when a detector is added.
func TestOverlapResolution(t *testing.T) {
	// A valid card sits inside text that also satisfies the bank-account
	// pattern and its context requirement. Exactly one span must survive.
	text := "debit the account 4111111111111111 today"
	ms := NewEngine().Find(text)

	n := 0
	for _, m := range ms {
		if m.Start < 34 && m.End > 18 {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly one match over the digits, got %d: %v", n, ms)
	}
	for _, m := range ms {
		if m.Value == "4111111111111111" && m.Type != CreditCard {
			t.Errorf("expected CREDIT_CARD to win overlap, got %s", m.Type)
		}
	}
}

func TestMatchesAreDisjointAndOrdered(t *testing.T) {
	text := "Anwesha (anwesha@example.com, 9876543210) paid with 4111 1111 1111 1111 from HDFC0001234"
	ms := NewEngine().Find(text)
	if len(ms) < 4 {
		t.Fatalf("expected at least 4 matches, got %d: %v", len(ms), ms)
	}
	for i := 1; i < len(ms); i++ {
		if ms[i].Start < ms[i-1].End {
			t.Errorf("matches overlap or are unordered: %v then %v", ms[i-1], ms[i])
		}
	}
}

func TestLuhn(t *testing.T) {
	valid := []string{"4111111111111111", "5500005555555559", "378282246310005"}
	invalid := []string{"4111111111111112", "1234567890123456", "0000"}
	for _, v := range valid {
		if !luhn(v) {
			t.Errorf("expected %s to pass Luhn", v)
		}
	}
	for _, v := range invalid {
		if luhn(v) {
			t.Errorf("expected %s to fail Luhn", v)
		}
	}
}

func TestVerhoeff(t *testing.T) {
	if !verhoeff("234567890124") {
		t.Error("expected known-good aadhaar to validate")
	}
	if verhoeff("234567890123") {
		t.Error("expected altered check digit to fail")
	}
	if verhoeff("23456789012") {
		t.Error("expected wrong-length input to fail")
	}
}
