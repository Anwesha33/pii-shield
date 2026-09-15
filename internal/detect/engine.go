package detect

import "sort"

// Engine runs a set of detectors over a document and reconciles their output
// into a single non-overlapping list of matches.
//
// Reconciliation matters more than it sounds. A 16-digit card number contains
// a 12-digit substring that can satisfy the Aadhaar pattern; "account number
// 4111111111111111" is matched by both the card and the bank-account detector.
// Emitting both would produce nested redactions and double-count every
// benchmark. Engine resolves these collisions with one explicit rule.
type Engine struct {
	detectors []Detector

	// minConfidence drops matches below a threshold before overlap
	// resolution. Zero keeps everything.
	minConfidence float64
}

// NewEngine returns an Engine with the built-in detector set.
func NewEngine() *Engine {
	return &Engine{detectors: builtinDetectors()}
}

// NewEngineWith returns an Engine restricted to the named entity types. Types
// not listed are not scanned for at all, which is how the policy layer turns
// an entity class off without paying for its regex pass.
func NewEngineWith(enabled []EntityType) *Engine {
	want := make(map[EntityType]bool, len(enabled))
	for _, t := range enabled {
		want[t] = true
	}
	var ds []Detector
	for _, d := range builtinDetectors() {
		if want[d.Type()] {
			ds = append(ds, d)
		}
	}
	return &Engine{detectors: ds}
}

// SetMinConfidence drops matches scoring below min.
func (e *Engine) SetMinConfidence(min float64) { e.minConfidence = min }

// Detectors exposes the active detector set, for reporting.
func (e *Engine) Detectors() []Detector { return e.detectors }

// Find returns non-overlapping matches in document order.
func (e *Engine) Find(text string) []Match {
	var all []Match
	for _, d := range e.detectors {
		for _, m := range d.Find(text) {
			if m.Confidence >= e.minConfidence {
				all = append(all, m)
			}
		}
	}
	return resolveOverlaps(all, e.priority())
}

// priority maps a detector's position in the configured order to a rank, so
// that ties in the overlap rule fall back to the order declared in
// builtinDetectors rather than to map iteration order.
func (e *Engine) priority() map[EntityType]int {
	p := make(map[EntityType]int, len(e.detectors))
	for i, d := range e.detectors {
		if _, seen := p[d.Type()]; !seen {
			p[d.Type()] = i
		}
	}
	return p
}

// resolveOverlaps reduces a set of possibly-overlapping matches to a disjoint
// set, using a longest-match-wins rule:
//
//  1. Longer spans beat shorter ones. A 16-digit card beats the 12-digit
//     Aadhaar candidate sitting inside it.
//  2. On equal length, higher confidence wins. A checksum-validated match
//     beats a purely lexical one covering the same bytes.
//  3. On equal confidence, the detector declared earlier wins, so the outcome
//     is deterministic rather than dependent on iteration order.
//
// Greedy selection is correct here because the winner of any collision is
// fully determined by the pair, and spans are short relative to the document;
// an interval-scheduling optimum would buy nothing on real inputs.
func resolveOverlaps(ms []Match, priority map[EntityType]int) []Match {
	if len(ms) <= 1 {
		return ms
	}
	sort.SliceStable(ms, func(i, j int) bool {
		a, b := ms[i], ms[j]
		if a.Len() != b.Len() {
			return a.Len() > b.Len()
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return priority[a.Type] < priority[b.Type]
	})

	var kept []Match
	for _, m := range ms {
		conflict := false
		for _, k := range kept {
			if m.Overlaps(k) {
				conflict = true
				break
			}
		}
		if !conflict {
			kept = append(kept, m)
		}
	}

	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}
