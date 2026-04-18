package securitytxt

import (
	"strings"
	"testing"
)

func TestValidateCollectsFieldIssues(t *testing.T) {
	txt := &SecurityTxt{
		IsRFCCompliant:     true,
		Contact:            []string{"not a uri"},
		Canonical:          []string{"http://example.com/security.txt"},
		PreferredLanguages: "english_us",
	}

	err := txt.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want non-nil")
	}

	wantIssues := []string{
		"Missing required 'Expires' field",
		`invalid Contact value "not a uri": missing URI scheme`,
		`invalid Canonical value "http://example.com/security.txt": must use https`,
		`invalid Preferred-Languages value "english_us": contains invalid language tag "english_us"`,
	}

	for _, want := range wantIssues {
		if !contains(txt.ComplianceIssues, want) {
			t.Fatalf("ComplianceIssues missing %q: %v", want, txt.ComplianceIssues)
		}
	}
}

func TestParseReportsHumanLineNumbers(t *testing.T) {
	txt := &SecurityTxt{IsRFCCompliant: true}

	err := Parse([]byte("Preferred-Languages: en\nPreferred-Languages: fr\n"), txt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(txt.ParseErrors()) != 1 {
		t.Fatalf("ParseErrors() len = %d, want 1", len(txt.ParseErrors()))
	}

	if got := txt.ParseErrors()[0].Error(); !strings.Contains(got, "line 2") {
		t.Fatalf("ParseErrors()[0] = %q, want line 2", got)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
