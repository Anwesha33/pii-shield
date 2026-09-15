// Package redact turns detected entities into a safe outbound payload and
// restores the originals on the way back.
package redact

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Anwesha33/pii-shield/internal/detect"
	"github.com/Anwesha33/pii-shield/internal/policy"
	"github.com/Anwesha33/pii-shield/internal/vault"
)

// Redactor applies a policy to text using a detection engine.
type Redactor struct {
	engine *detect.Engine
	pol    *policy.Policy
}

func New(engine *detect.Engine, pol *policy.Policy) *Redactor {
	return &Redactor{engine: engine, pol: pol}
}

// NewDefault builds a Redactor with the default policy and the detector set it
// implies.
func NewDefault() *Redactor {
	pol := policy.Default()
	return New(detect.NewEngineWith(pol.EnabledTypes()), pol)
}

// BlockedError reports that a request may not proceed because it contains an
// entity the policy refuses to transmit under any transformation.
type BlockedError struct {
	Type  detect.EntityType
	Count int
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("request blocked: contains %d %s value(s) which policy forbids sending to a third party", e.Count, e.Type)
}

// Result describes one redaction pass.
type Result struct {
	// Text is the safe payload to send upstream.
	Text string
	// Decisions records what happened to every match, in document order. This
	// is the audit trail: for a compliance product, "what did you do and why"
	// has to be answerable after the fact.
	Decisions []policy.Decision
	// Counts tallies acted-on entities per type, for metrics.
	Counts map[detect.EntityType]int
}

// Redact scans text, applies the policy, and writes replacements into v.
//
// Replacement walks the match list in reverse document order. Rewriting from
// the end means every not-yet-processed span keeps its original offsets; going
// forwards would invalidate every offset after the first substitution of a
// different length, which is the classic bug in this kind of code.
func (r *Redactor) Redact(text string, v *vault.Vault) (*Result, error) {
	matches := r.engine.Find(text)
	res := &Result{Counts: map[detect.EntityType]int{}}

	decisions := make([]policy.Decision, 0, len(matches))
	for _, m := range matches {
		decisions = append(decisions, r.pol.Decide(m))
	}
	res.Decisions = decisions

	// Blocking is resolved before any rewriting: a blocked request never
	// produces a partially redacted payload that could be logged or retried.
	blocked := map[detect.EntityType]int{}
	for _, d := range decisions {
		if d.Action == policy.Block {
			blocked[d.Match.Type]++
		}
	}
	for t, n := range blocked {
		return nil, &BlockedError{Type: t, Count: n}
	}

	b := []byte(text)
	for i := len(decisions) - 1; i >= 0; i-- {
		d := decisions[i]
		var replacement string
		switch d.Action {
		case policy.Redact:
			replacement = v.Tokenize(string(d.Match.Type), d.Match.Value)
		case policy.Mask:
			replacement = policy.MaskValue(d.Match.Value)
		case policy.Allow:
			continue
		}
		b = append(b[:d.Match.Start], append([]byte(replacement), b[d.Match.End:]...)...)
		res.Counts[d.Match.Type]++
	}

	res.Text = string(b)
	return res, nil
}

// tokenPattern matches any placeholder this package mints.
var tokenPattern = regexp.MustCompile(`\[\[([A-Z_]+)_(\d+)\]\]`)

// Rehydrate restores original values in text using v.
//
// Unknown tokens are left untouched rather than erased. If the model invents
// [[EMAIL_9]] that was never minted, replacing it with an empty string would
// silently corrupt the response; leaving it visible makes the model's mistake
// obvious to the caller and to anyone reading the logs.
func Rehydrate(text string, v *vault.Vault) string {
	return tokenPattern.ReplaceAllStringFunc(text, func(tok string) string {
		if val, ok := v.Resolve(tok); ok {
			return val
		}
		return tok
	})
}

// ScanOutput reports entities found in a model response that were never in the
// request. This is the egress half of the problem: a model can reproduce
// training data, hallucinate a plausible-looking card number, or echo a value
// the request layer failed to catch. Detecting it does not prevent it, but it
// turns a silent leak into an alert.
func ScanOutput(text string, v *vault.Vault) []detect.Match {
	known := v.Tokens()
	seen := make(map[string]bool, len(known))
	for _, val := range known {
		seen[val] = true
	}

	var leaked []detect.Match
	for _, m := range detect.NewEngine().Find(text) {
		if !seen[m.Value] {
			leaked = append(leaked, m)
		}
	}
	return leaked
}

// Summary renders a one-line description of a result, used in logs.
func (r *Result) Summary() string {
	if len(r.Counts) == 0 {
		return "no entities redacted"
	}
	parts := make([]string, 0, len(r.Counts))
	for _, t := range detect.AllTypes {
		if n, ok := r.Counts[t]; ok {
			parts = append(parts, fmt.Sprintf("%s=%d", t, n))
		}
	}
	return strings.Join(parts, " ")
}
