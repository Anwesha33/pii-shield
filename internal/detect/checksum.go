package detect

// Checksum helpers. These exist because a bare regex for a 12- or 16-digit
// number matches an enormous amount of text that is not a card or an Aadhaar
// number — order IDs, timestamps, tracking numbers. Validating the check digit
// is what makes these detectors usable in production rather than a false
// positive generator.

// luhn reports whether digits satisfies the Luhn check used by payment cards.
// digits must contain only ASCII digits.
func luhn(digits string) bool {
	if len(digits) < 12 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// verhoeffTable is the multiplication table for the dihedral group D5.
var verhoeffTable = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

// verhoeffPerm is the permutation table applied per digit position.
var verhoeffPerm = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// verhoeff reports whether digits satisfies the Verhoeff checksum that UIDAI
// uses for Aadhaar numbers.
func verhoeff(digits string) bool {
	if len(digits) != 12 {
		return false
	}
	c := 0
	for i := 0; i < len(digits); i++ {
		d := int(digits[len(digits)-1-i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		c = verhoeffTable[c][verhoeffPerm[i%8][d]]
	}
	return c == 0
}

// digitsOnly strips the separators humans put inside long numbers, so that
// "4111-1111 1111 1111" and "4111111111111111" validate identically.
func digitsOnly(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
