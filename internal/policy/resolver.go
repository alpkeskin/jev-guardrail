package policy

import "sort"

// Resolver selects the policy that applies to a client ID.
type Resolver interface {
	// Resolve returns the client's policy, or the default policy when
	// clientID is empty or unknown. found reports whether a client-specific
	// policy was used.
	Resolve(clientID string) (p Policy, found bool)
}

// Store is an immutable, in-memory set of validated policies.
type Store struct {
	def      Policy
	byClient map[string]Policy
}

var _ Resolver = (*Store)(nil)

// Resolve implements Resolver.
func (s *Store) Resolve(clientID string) (Policy, bool) {
	if clientID == "" || clientID == DefaultClientID {
		return s.def, false
	}
	if p, ok := s.byClient[clientID]; ok {
		return p, true
	}
	return s.def, false
}

// Default returns the default policy.
func (s *Store) Default() Policy { return s.def }

// ClientIDs returns all loaded client IDs, sorted.
func (s *Store) ClientIDs() []string {
	ids := make([]string, 0, len(s.byClient))
	for id := range s.byClient {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
