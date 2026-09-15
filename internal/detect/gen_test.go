package detect

import "testing"

// TestGenerateFixtures is a helper used once to produce checksum-valid sample
// values for the test corpus. Skipped by default.
func TestGenerateFixtures(t *testing.T) {
	t.Skip("fixture generator; run with -run TestGenerateFixtures -v to regenerate")
	found := 0
	for n := 234567890120; n < 234567890200 && found < 3; n++ {
		s := itoa12(n)
		if verhoeff(s) {
			t.Logf("valid aadhaar: %s", s)
			found++
		}
	}
}

func itoa12(n int) string {
	b := make([]byte, 12)
	for i := 11; i >= 0; i-- {
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b)
}
