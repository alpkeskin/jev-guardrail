package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/alpkeskin/jev-guardrail/internal/policy"
)

// TestDeployPoliciesInSync keeps the Kubernetes policy copies valid and
// the base default identical to policies/default.yaml.
func TestDeployPoliciesInSync(t *testing.T) {
	root := "../.."
	want, err := os.ReadFile(filepath.Join(root, "policies/default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "deploy/kubernetes/base/policies/default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Error("deploy/kubernetes/base/policies/default.yaml differs from policies/default.yaml")
	}
	if _, err := policy.Load(filepath.Join(root, "deploy/kubernetes/base/policies")); err != nil {
		t.Errorf("base policies: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(root, "deploy/kubernetes/overlays/*/policies/*.yaml"))
	if len(files) == 0 {
		t.Fatal("no overlay policies found")
	}
	for _, f := range files {
		if _, err := policy.LoadFile(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
