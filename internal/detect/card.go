package detect

// Card brand validation.
//
// Luhn alone is not enough. Luhn is a single check digit, so roughly one in ten
// arbitrary digit strings passes it by chance -- an 18-digit tracking number in
// the evaluation corpus did exactly that. Real cards are additionally
// constrained in length and in their issuer identification number, and checking
// both turns a noisy detector into a precise one.

// cardSpec is one issuer's accepted shape.
type cardSpec struct {
	prefixes []string
	lengths  []int
}

var cardSpecs = []cardSpec{
	{prefixes: []string{"4"}, lengths: []int{13, 16, 19}},                                                // Visa
	{prefixes: []string{"51", "52", "53", "54", "55"}, lengths: []int{16}},                               // Mastercard
	{prefixes: []string{"34", "37"}, lengths: []int{15}},                                                 // Amex
	{prefixes: []string{"6011", "65", "644", "645", "646", "647", "648", "649"}, lengths: []int{16, 19}}, // Discover
	{prefixes: []string{"300", "301", "302", "303", "304", "305", "36", "38"}, lengths: []int{14}},       // Diners
	{prefixes: []string{"60", "81", "82", "508"}, lengths: []int{16}},                                    // RuPay
	{prefixes: []string{"35"}, lengths: []int{16, 17, 18, 19}},                                           // JCB
}

// validCard reports whether digits is plausibly a payment card number: correct
// length for its issuer, a recognised prefix, and a valid Luhn check digit.
func validCard(digits string) bool {
	if !luhn(digits) {
		return false
	}
	for _, spec := range cardSpecs {
		if !containsInt(spec.lengths, len(digits)) {
			continue
		}
		for _, p := range spec.prefixes {
			if len(digits) >= len(p) && digits[:len(p)] == p {
				return true
			}
		}
	}
	// Mastercard's 2-series range is expressed numerically rather than as a
	// prefix list, so it is checked separately.
	if len(digits) == 16 {
		if n := atoi(digits[:4]); n >= 2221 && n <= 2720 {
			return true
		}
	}
	return false
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// isRepeatedDigits reports whether every character is the same, which no real
// identifier ever is. Placeholders like 000000000000 and 111111111111 are
// common in test data and documentation, and redacting them is pure noise.
func isRepeatedDigits(s string) bool {
	d := digitsOnly(s)
	if len(d) < 2 {
		return false
	}
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return true
}
