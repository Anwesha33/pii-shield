// Package detect finds personally identifiable information inside free text.
//
// The package is deliberately independent of how the findings are used: it
// reports spans and lets the caller decide what to do with them. That keeps
// the detectors testable in isolation and lets the redaction policy change
// without touching detection logic.
package detect

import "fmt"

// EntityType identifies a class of sensitive value.
type EntityType string

const (
	Email       EntityType = "EMAIL"
	PhoneIN     EntityType = "PHONE_IN"
	PhoneUS     EntityType = "PHONE_US"
	Aadhaar     EntityType = "AADHAAR"
	PAN         EntityType = "PAN"
	CreditCard  EntityType = "CREDIT_CARD"
	IFSC        EntityType = "IFSC"
	UPI         EntityType = "UPI_ID"
	BankAccount EntityType = "BANK_ACCOUNT"
	IPAddress   EntityType = "IP_ADDRESS"
	PassportIN  EntityType = "PASSPORT_IN"
	APIKey      EntityType = "API_KEY"
	JWT         EntityType = "JWT"
	PersonName  EntityType = "PERSON_NAME"
)

// AllTypes is the canonical ordering used by reports and the benchmark, so
// that output is stable across runs.
var AllTypes = []EntityType{
	Email, PhoneIN, PhoneUS, Aadhaar, PAN, CreditCard, IFSC, UPI,
	BankAccount, IPAddress, PassportIN, APIKey, JWT, PersonName,
}

// Match is a single detected span. Start and End are byte offsets into the
// scanned string, half-open, so text[Start:End] is exactly the matched value.
type Match struct {
	Type  EntityType `json:"type"`
	Start int        `json:"start"`
	End   int        `json:"end"`
	Value string     `json:"value"`

	// Confidence is the detector's own estimate in [0,1]. Detectors backed by
	// a checksum report high confidence; purely lexical ones report less, and
	// the policy layer can be configured to ignore low-confidence findings.
	Confidence float64 `json:"confidence"`

	// Detector names the rule that produced the match. Carried purely for
	// debugging and for the per-detector breakdown in the benchmark report.
	Detector string `json:"detector"`
}

func (m Match) String() string {
	return fmt.Sprintf("%s[%d:%d]=%q (%.2f via %s)", m.Type, m.Start, m.End, m.Value, m.Confidence, m.Detector)
}

// Len is the byte length of the matched span.
func (m Match) Len() int { return m.End - m.Start }

// Overlaps reports whether two matches share at least one byte.
func (m Match) Overlaps(o Match) bool { return m.Start < o.End && o.Start < m.End }

// Detector finds zero or more matches of a single entity class in text.
//
// Implementations must be safe for concurrent use: the proxy shares one
// detector set across all in-flight requests.
type Detector interface {
	// Name identifies the detector in reports.
	Name() string
	// Type is the entity class this detector produces.
	Type() EntityType
	// Find returns matches in document order.
	Find(text string) []Match
}
