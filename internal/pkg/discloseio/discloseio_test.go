package discloseio

import (
	"testing"
	"time"

	"github.com/disclose/diosts/pkg/securitytxt"
)

func TestFromSecurityTxtMapsContactsAndProgramName(t *testing.T) {
	txt := &securitytxt.SecurityTxt{
		Domain:             "example.com",
		Contact:            []string{"mailto:security@example.com", "https://example.com/security"},
		PreferredLanguages: "en, fr",
		Expires:            time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		IsRFCCompliant:     true,
	}

	fields := FromSecurityTxt("vtest", txt)

	if fields.ProgramName != "example.com" {
		t.Fatalf("ProgramName = %q, want %q", fields.ProgramName, "example.com")
	}
	if fields.ContactEmail != "security@example.com" {
		t.Fatalf("ContactEmail = %q, want %q", fields.ContactEmail, "security@example.com")
	}
	if fields.ContactURL != "https://example.com/security" {
		t.Fatalf("ContactURL = %q, want %q", fields.ContactURL, "https://example.com/security")
	}
}
