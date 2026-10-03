package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

const validDefault = `version: "1"
client_id: default
rules:
  prompt_injection:
    enabled: true
    threshold: 0.80
    action: block
`

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func clientPolicy(id, extra string) string {
	return "version: \"1\"\nclient_id: " + id + "\nrules:\n  jailbreak:\n    threshold: 0.5\n    action: review\n" + extra
}

func TestLoadDefaultPolicy(t *testing.T) {
	store, err := Load(writeFiles(t, map[string]string{"default.yaml": validDefault}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	def := store.Default()
	if def.ClientID != "default" || def.Version != "1" {
		t.Fatalf("unexpected default policy: %+v", def)
	}
	r, ok := def.Rules[guardrail.CategoryPromptInjection]
	if !ok || !r.Enabled || r.Threshold != 0.80 || r.Action != guardrail.ActionBlock {
		t.Fatalf("unexpected rule: %+v", r)
	}
}

func TestLoadRepositoryPolicies(t *testing.T) {
	for _, dir := range []string{"../../policies", "../../tests/fixtures/policies"} {
		if _, err := Load(dir); err != nil {
			t.Errorf("Load(%s): %v", dir, err)
		}
	}
}

func TestLoadClientPolicyIndexedByClientID(t *testing.T) {
	store, err := Load(writeFiles(t, map[string]string{
		"default.yaml": validDefault,
		"foo.yaml":     clientPolicy("acme-production", ""),
		"notes.txt":    "ignored",
		".hidden.yaml": "not: [valid",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, found := store.Resolve("acme-production")
	if !found || p.ClientID != "acme-production" {
		t.Fatalf("expected acme-production policy, got %+v found=%v", p, found)
	}
	if _, found := store.Resolve("foo"); found {
		t.Fatal("filename must not be used as client id")
	}
	r := p.Rules[guardrail.CategoryJailbreak]
	if !r.Enabled {
		t.Fatal("enabled must default to true")
	}
	if r.Action != guardrail.ActionReview {
		t.Fatalf("action = %q", r.Action)
	}
}

func TestResolve(t *testing.T) {
	store, err := Load(writeFiles(t, map[string]string{
		"default.yaml": validDefault,
		"acme.yaml":    clientPolicy("acme-production", ""),
	}))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, clientID, want string
		found                bool
	}{
		{"no client id", "", "default", false},
		{"known client id", "acme-production", "acme-production", true},
		{"unknown client id", "nope", "default", false},
		{"explicit default", "default", "default", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, found := store.Resolve(tc.clientID)
			if p.ClientID != tc.want || found != tc.found {
				t.Fatalf("Resolve(%q) = %q, %v; want %q, %v", tc.clientID, p.ClientID, found, tc.want, tc.found)
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		wantErr string
	}{
		{"missing default", map[string]string{"a.yaml": clientPolicy("a", "")}, "default policy"},
		{"empty dir", map[string]string{}, "default policy"},
		{"malformed default", map[string]string{"default.yaml": "version: [1"}, "malformed YAML"},
		{"empty default", map[string]string{"default.yaml": ""}, "empty"},
		{"malformed client", map[string]string{"default.yaml": validDefault, "a.yaml": "rules: {"}, "malformed YAML"},
		{"duplicate client ids", map[string]string{
			"default.yaml": validDefault,
			"a.yaml":       clientPolicy("acme", ""),
			"b.yaml":       clientPolicy("acme", ""),
		}, "duplicate client_id"},
		{"default with wrong client id", map[string]string{"default.yaml": clientPolicy("other", "")}, "must declare client_id"},
		{"default client id reused", map[string]string{"default.yaml": validDefault, "x.yaml": clientPolicy("default", "")}, "reserved"},
		{"threshold above 1", map[string]string{"default.yaml": strings.Replace(validDefault, "0.80", "1.5", 1)}, "threshold"},
		{"threshold zero", map[string]string{"default.yaml": strings.Replace(validDefault, "0.80", "0", 1)}, "threshold"},
		{"threshold negative", map[string]string{"default.yaml": strings.Replace(validDefault, "0.80", "-0.2", 1)}, "threshold"},
		{"threshold missing", map[string]string{"default.yaml": strings.Replace(validDefault, "    threshold: 0.80\n", "", 1)}, "threshold is required"},
		{"threshold not a number", map[string]string{"default.yaml": strings.Replace(validDefault, "0.80", "high", 1)}, "malformed YAML"},
		{"invalid action", map[string]string{"default.yaml": strings.Replace(validDefault, "block", "explode", 1)}, "invalid action"},
		{"missing action", map[string]string{"default.yaml": strings.Replace(validDefault, "    action: block\n", "", 1)}, "invalid action"},
		{"unknown category", map[string]string{"default.yaml": validDefault + "  telepathy:\n    threshold: 0.5\n    action: block\n"}, "unknown taxonomy category"},
		{"uppercase category key", map[string]string{"default.yaml": validDefault + "  JAILBREAK:\n    threshold: 0.5\n    action: block\n"}, "unknown taxonomy category"},
		{"duplicate category via alias", map[string]string{"default.yaml": validDefault +
			"  system_prompt_extraction:\n    threshold: 0.5\n    action: block\n" +
			"  system_prompt_leak:\n    threshold: 0.5\n    action: block\n"}, "already configured"},
		{"unknown field", map[string]string{"default.yaml": strings.Replace(validDefault, "action: block", "action: block\n    treshold: 0.1", 1)}, "malformed YAML"},
		{"unsupported version", map[string]string{"default.yaml": strings.Replace(validDefault, `"1"`, `"2"`, 1)}, "unsupported version"},
		{"no rules", map[string]string{"default.yaml": "version: \"1\"\nclient_id: default\n"}, "at least one rule"},
		{"invalid client id", map[string]string{"default.yaml": validDefault, "x.yaml": clientPolicy(`"../etc"`, "")}, "invalid client_id"},
		{"multiple documents", map[string]string{"default.yaml": validDefault + "---\n" + validDefault}, "exactly one YAML document"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeFiles(t, tc.files))
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadMissingDirectory(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected error")
	}
}

func TestDisabledRule(t *testing.T) {
	store, err := Load(writeFiles(t, map[string]string{
		"default.yaml": strings.Replace(validDefault, "enabled: true", "enabled: false", 1),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Default().EnabledCategories(); len(got) != 0 {
		t.Fatalf("EnabledCategories = %v", got)
	}
}

func TestDocumentSeparatorsAccepted(t *testing.T) {
	for name, content := range map[string]string{
		"leading":  "---\n" + validDefault,
		"trailing": validDefault + "---\n",
		"both":     "---\n" + validDefault + "---\n...\n",
	} {
		if _, err := Load(writeFiles(t, map[string]string{"default.yaml": content})); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDuplicateYAMLKeyRejected(t *testing.T) {
	_, err := Load(writeFiles(t, map[string]string{"default.yaml": validDefault + "  prompt_injection:\n    threshold: 0.1\n    action: review\n"}))
	if err == nil {
		t.Fatal("duplicate rule key must fail")
	}
}
