package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

// TestReadmeDocumentsTaxonomy keeps the README taxonomy in sync with the
// code: every category, policy key, failure code and content type must be
// listed.
func TestReadmeDocumentsTaxonomy(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(data)
	want := []string{}
	for _, c := range guardrail.Categories() {
		want = append(want, "`"+string(c.Category)+"`", "`"+c.RuleKey+"`")
	}
	for _, c := range guardrail.FailureCodes() {
		want = append(want, "`"+string(c)+"`")
	}
	for _, c := range guardrail.ContentTypes() {
		want = append(want, "`"+string(c)+"`")
	}
	for _, w := range want {
		if !strings.Contains(readme, w) {
			t.Errorf("README does not document %s", w)
		}
	}
}
