package discloseio

import (
	"net/url"
	"strings"
	"time"

	"github.com/disclose/diosts/pkg/securitytxt"
)

type Fields struct {
	ProgramName string `json:"program_name,omitempty"`
	SecurityTxtDomain string `json:"security_txt_domain,omitempty"`
	PolicyURL string `json:"policy_url,omitempty"`
	ContactURL string `json:"contact_url"`
	LaunchDate *time.Time `json:"launch_date,omitempty"`
	OffersBounty string `json:"offers_bounty,omitempty"`
	OffersSwag bool `json:"offers_swag,omitempty"`
	HallOfFame string `json:"hall_of_fame,omitempty"`
	SafeHarbor string `json:"safe_harbor,omitempty"`
	PublicDisclosure string `json:"public_disclosure,omitempty"`
	DisclosureTimelineDays int `json:"disclosure_timeline,omitempty"`
	PGPKey string `json:"pgp_key,omitempty"`
	Hiring string `json:"hiring,omitempty"`
	SecuritytxtURL string `json:"securitytxt_url,omitempty"`
	PreferredLanguages string `json:"preferred_languages,omitempty"`
}

func FromSecurityTxt(txt *securitytxt.SecurityTxt) *Fields {
	f := &Fields{
		SecurityTxtDomain: txt.Domain,
		PreferredLanguages: txt.PreferredLanguages,
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

	// For contact, we'll find the first web link. If not found, we resort
	// to just the first entry
	for _, c := range(txt.Contact) {
		url, err := url.Parse(c)
		if err != nil {
			continue
		}

		if strings.HasPrefix(url.Scheme, "http") {
			f.ContactURL = c
			break
		}
	}

	if len(txt.Contact) > 0 && f.ContactURL == "" {
		f.ContactURL = txt.Contact[0]
	}

	return f
}
