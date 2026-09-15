// Package policy decides what happens to each class of detected entity.
//
// Detection and decision are kept apart on purpose. "Did we find a card
// number" is a factual question with a testable answer; "may a card number
// leave the building" is a business rule that differs per deployment and
// changes without warning. Splitting them means a compliance change is a YAML
// edit rather than a code change.
package policy

import (
	"fmt"
	"strings"

	"github.com/Anwesha33/pii-shield/internal/detect"
)

// Action is what to do with a detected entity.
type Action string

const (
	// Redact replaces the value with a reversible token and restores it in the
	// response. The model never sees the value; the caller sees it unchanged.
	Redact Action = "redact"

	// Mask replaces the value irreversibly, keeping a hint of its shape
	// (last four digits). Used where even the proxy should not hold the value
	// in memory, and where the caller does not need it back.
	Mask Action = "mask"

	// Block rejects the whole request. Used for entities that must never be
	// sent to a third party under any transformation, such as live API keys.
	Block Action = "block"

	// Allow passes the value through untouched. Present so that turning a
	// detector off is an explicit, auditable decision rather than a deletion.
	Allow Action = "allow"
)

// Rule binds an entity type to an action.
type Rule struct {
	Type          detect.EntityType `yaml:"type"`
	Action        Action            `yaml:"action"`
	MinConfidence float64           `yaml:"min_confidence"`
}

// Policy is an ordered rule set with a default for unlisted types.
type Policy struct {
	Default Action          `yaml:"default"`
	Rules   map[string]Rule `yaml:"-"`
}

// Decision is the outcome for one match.
type Decision struct {
	Match  detect.Match
	Action Action
	Reason string
}

// Default returns the policy used when no configuration file is supplied:
// redact everything that is reversible, block credentials outright.
//
// Blocking rather than redacting credentials is the one asymmetric choice
// here. A tokenized API key is still an API key the moment the response is
// re-hydrated, and no legitimate prompt needs one, so the safe default is to
// refuse the request and make the caller remove it.
func Default() *Policy {
	p := &Policy{Default: Redact, Rules: map[string]Rule{}}
	for _, t := range detect.AllTypes {
		p.Rules[string(t)] = Rule{Type: t, Action: Redact, MinConfidence: 0.5}
	}
	p.Rules[string(detect.APIKey)] = Rule{Type: detect.APIKey, Action: Block, MinConfidence: 0.9}
	p.Rules[string(detect.JWT)] = Rule{Type: detect.JWT, Action: Block, MinConfidence: 0.9}
	p.Rules[string(detect.CreditCard)] = Rule{Type: detect.CreditCard, Action: Mask, MinConfidence: 0.9}
	// Names are the least reliable detector in the set, so they are held to a
	// lower bar for being acted on at all but still redacted when found.
	p.Rules[string(detect.PersonName)] = Rule{Type: detect.PersonName, Action: Redact, MinConfidence: 0.5}
	return p
}

// Decide resolves the action for a single match.
func (p *Policy) Decide(m detect.Match) Decision {
	r, ok := p.Rules[string(m.Type)]
	if !ok {
		return Decision{Match: m, Action: p.Default, Reason: "no rule; default applied"}
	}
	if m.Confidence < r.MinConfidence {
		return Decision{Match: m, Action: Allow, Reason: fmt.Sprintf("confidence %.2f below threshold %.2f", m.Confidence, r.MinConfidence)}
	}
	return Decision{Match: m, Action: r.Action, Reason: "matched rule for " + string(m.Type)}
}

// EnabledTypes lists the entity types the policy does anything with, so the
// detection engine can skip scanning for classes that are set to allow.
func (p *Policy) EnabledTypes() []detect.EntityType {
	var out []detect.EntityType
	for _, t := range detect.AllTypes {
		if r, ok := p.Rules[string(t)]; !ok || r.Action != Allow {
			out = append(out, t)
		}
	}
	return out
}

// MaskValue produces the irreversible replacement for a masked entity,
// preserving the last four characters where the value is long enough. Keeping
// a suffix is what makes masking usable in practice: support staff can still
// confirm "the card ending 1111" without the number ever leaving the building.
func MaskValue(value string) string {
	trimmed := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, value)
	if len(trimmed) >= 4 {
		return "****" + trimmed[len(trimmed)-4:]
	}
	return "****"
}
