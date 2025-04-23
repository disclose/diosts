package discloseio

import (
	"fmt"
	"net/url"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/disclose/diosts/pkg/securitytxt"
)

// diosts-specific metadata
type Metadata struct {
	SecurityTxtDomain string     `json:"security_txt_domain,omitempty"`
	Source            string     `json:"source,omitempty"`
	RetrievalURL      string     `json:"retrieval_url,omitempty"`
	LastUpdate        *time.Time `json:"last_update,omitempty"`
}

func NewMetadata(version string) *Metadata {
	now := time.Now().Truncate(time.Second).UTC()

	m := &Metadata{
		Source:     fmt.Sprintf("diosts-%s", version),
		LastUpdate: &now,
	}

	return m
}

type Fields struct {
	*Metadata

	ProgramName            string     `json:"program_name,omitempty"`
	PolicyURL              string     `json:"policy_url,omitempty"`
	ContactURL             string     `json:"contact_url"`
	ContactEmail           string     `json:"contact_email,omitempty"`
	LaunchDate             *time.Time `json:"launch_date,omitempty"`
	OffersBounty           string     `json:"offers_bounty,omitempty"`
	OffersSwag             bool       `json:"offers_swag,omitempty"`
	HallOfFame             string     `json:"hall_of_fame,omitempty"`
	SafeHarbor             string     `json:"safe_harbor,omitempty"`
	PublicDisclosure       string     `json:"public_disclosure,omitempty"`
	DisclosureTimelineDays int        `json:"disclosure_timeline,omitempty"`
	PGPKey                 string     `json:"pgp_key,omitempty"`
	Hiring                 string     `json:"hiring,omitempty"`
	SecuritytxtURL         string     `json:"securitytxt_url,omitempty"`
	PreferredLanguages     string     `json:"preferred_languages,omitempty"`
	ExpiresAt              *time.Time `json:"expires_at,omitempty"`
	RFCCompliant           bool       `json:"rfc_compliant,omitempty"`
	ComplianceIssues       []string   `json:"compliance_issues,omitempty"`
}

func FromSecurityTxt(version string, txt *securitytxt.SecurityTxt) *Fields {
	m := NewMetadata(version)
	m.SecurityTxtDomain = txt.Domain
	m.RetrievalURL = txt.RetrievedFrom

	f := &Fields{
		Metadata:           m,
		PreferredLanguages: txt.PreferredLanguages,
		RFCCompliant:       txt.IsRFCCompliant,
		ComplianceIssues:   txt.ComplianceIssues,
	}

	// Add Expires field
	if !txt.Expires.IsZero() {
		expiresAt := txt.Expires
		f.ExpiresAt = &expiresAt
	}

	// For fields that can have multiple entries in security.txt, we
	// choose the first one
	if len(txt.Policy) > 0 {
		f.PolicyURL = txt.Policy[0]
	}

	if len(txt.Acknowledgments) > 0 {
		f.HallOfFame = txt.Acknowledgments[0]
	}

	if len(txt.Encryption) > 0 {
		f.PGPKey = txt.Encryption[0]
	}

	if len(txt.Hiring) > 0 {
		f.Hiring = txt.Hiring[0]
	}

	if len(txt.Canonical) > 0 {
		f.SecuritytxtURL = txt.Canonical[0]
	}

	// Split up Contact in ContactURL and ContactEmail
	for _, c := range txt.Contact {
		url, err := url.Parse(c)
		if err != nil {
			// Should be done in securitytxt validation
			log.Warn().Str("domain", txt.Domain).Err(err).Msg("invalid uri for contact")
			continue
		}

		// We use the first of each
		switch url.Scheme {
		case "http", "https":
			if f.ContactURL != "" {
				f.ContactURL = c
			}
		case "mailto":
			if f.ContactEmail != "" {
				f.ContactEmail = c
			}
		default:
			log.Warn().Str("domain", txt.Domain).Str("scheme", url.Scheme).Msg("invalid url scheme for contact")
		}

	}

	if len(txt.Contact) > 0 && f.ContactURL == "" {
		f.ContactURL = txt.Contact[0]
	}

	return f
}
