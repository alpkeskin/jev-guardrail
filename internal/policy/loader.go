package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads every *.yaml / *.yml file in dir (non-recursive, dotfiles
// ignored), validates it and indexes it by its client_id.
//
// Load fails if default.yaml is missing or invalid, if any policy is
// invalid, or if two files declare the same client_id. Filenames are not
// identifiers: the client_id inside the file is authoritative.
func Load(dir string) (*Store, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy directory: %w", err)
	}

	defaultPath := filepath.Join(dir, DefaultFileName)
	if _, err := os.Stat(defaultPath); err != nil {
		return nil, fmt.Errorf("default policy %s is mandatory: %w", defaultPath, err)
	}

	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if ext := strings.ToLower(filepath.Ext(name)); ext == ".yaml" || ext == ".yml" {
			files = append(files, filepath.Join(dir, name))
		}
	}
	sort.Strings(files)

	store := &Store{byClient: map[string]Policy{}}
	var errs []error
	for _, path := range files {
		p, err := LoadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if path == defaultPath && p.ClientID != DefaultClientID {
			errs = append(errs, fmt.Errorf("policy %s: default policy must declare client_id %q, got %q", path, DefaultClientID, p.ClientID))
			continue
		}
		if path != defaultPath && p.ClientID == DefaultClientID {
			errs = append(errs, fmt.Errorf("policy %s: client_id %q is reserved for %s", path, DefaultClientID, DefaultFileName))
			continue
		}
		if prev, dup := store.byClient[p.ClientID]; dup {
			errs = append(errs, fmt.Errorf("duplicate client_id %q in %s and %s", p.ClientID, prev.Source, path))
			continue
		}
		store.byClient[p.ClientID] = p
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	def, ok := store.byClient[DefaultClientID]
	if !ok {
		return nil, fmt.Errorf("default policy %s could not be loaded", defaultPath)
	}
	store.def = def
	return store, nil
}

// LoadFile parses and validates a single policy file. Unknown YAML fields
// are rejected so typos cannot silently weaken a policy.
func LoadFile(path string) (Policy, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from the operator-configured policy directory
	if err != nil {
		return Policy{}, fmt.Errorf("policy %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var doc document
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return Policy{}, fmt.Errorf("policy %s: file is empty", path)
		}
		return Policy{}, fmt.Errorf("policy %s: malformed YAML: %w", path, err)
	}
	// Any further document must be empty (e.g. a trailing "---").
	for {
		var extra yaml.Node
		err := dec.Decode(&extra)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || !emptyDocument(&extra) {
			return Policy{}, fmt.Errorf("policy %s: must contain exactly one YAML document", path)
		}
	}
	return validate(doc, path)
}

func emptyDocument(n *yaml.Node) bool {
	if n.Kind == 0 {
		return true
	}
	if n.Kind == yaml.DocumentNode {
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode || c.Tag != "!!null" {
				return false
			}
		}
		return true
	}
	return false
}
