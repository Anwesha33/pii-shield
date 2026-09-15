// Package vault stores the mapping between a redaction token and the original
// sensitive value, so that a response can be re-hydrated on the way back.
package vault

import (
	"fmt"
	"sync"
)

// Vault maps placeholder tokens to the values they replaced.
//
// One Vault is created per request and discarded when the response is written.
// That is a deliberate scoping decision: a process-wide vault would let a
// token minted for one tenant re-hydrate inside another tenant's response,
// which is the worst possible failure for a product whose entire job is
// preventing data from crossing a boundary. Multi-turn conversations that need
// tokens to survive across requests use a Store instead, keyed by session.
type Vault struct {
	mu sync.RWMutex

	// forward maps token -> original value, used when re-hydrating.
	forward map[string]string
	// reverse maps original value -> token, so that the same value appearing
	// twice in one prompt gets the same token. Without this the model sees
	// [[EMAIL_1]] and [[EMAIL_2]] for one address and can no longer tell that
	// the sender and the recipient are the same person.
	reverse map[string]string
	// counters tracks the next ordinal per entity type.
	counters map[string]int
}

func New() *Vault {
	return &Vault{
		forward:  make(map[string]string),
		reverse:  make(map[string]string),
		counters: make(map[string]int),
	}
}

// Tokenize returns a stable placeholder for value within this vault, minting a
// new one on first sight.
//
// The token format is [[TYPE_N]]. Double brackets are used because they are
// rare in natural prose and in JSON payloads, so the odds of a user's own text
// colliding with a token are low; the surrounding type name keeps the prompt
// readable to the model, which matters because a model asked to reason about
// "[[PERSON_NAME_1]]" behaves far better than one handed "XXXXX".
func (v *Vault) Tokenize(entityType, value string) string {
	v.mu.Lock()
	defer v.mu.Unlock()

	if tok, ok := v.reverse[value]; ok {
		return tok
	}
	v.counters[entityType]++
	tok := fmt.Sprintf("[[%s_%d]]", entityType, v.counters[entityType])
	v.forward[tok] = value
	v.reverse[value] = tok
	return tok
}

// Resolve returns the original value behind a token.
func (v *Vault) Resolve(token string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	val, ok := v.forward[token]
	return val, ok
}

// Tokens returns a copy of the token -> value map.
func (v *Vault) Tokens() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make(map[string]string, len(v.forward))
	for k, val := range v.forward {
		out[k] = val
	}
	return out
}

// Len reports how many distinct values were tokenized.
func (v *Vault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.forward)
}
