package discloseio

import (
	"time"

	"github.com/hakluke/haksecuritytxt/pkg/securitytxt"
)

type Fields struct {
	ProgramName string `json:"program_name,omitempty"`
	PolicyURL []string `json:"policy_url,omitempty"`
	ContactURL []string `json:"contact_url"`
	LaunchDate *time.Time `json:"launch_date,omitempty"`
	OffersBounty string `json:"offers_bounty,omitempty"`
	OffersSwag bool `json:"offers_swag,omitempty"`
	HallOfFame []string `json:"hall_of_fame,omitempty"`
	SafeHarbor string `json:"safe_harbor,omitempty"`
	PublicDisclosure string `json:"public_disclosure,omitempty"`
	DisclosureTimelineDays int `json:"disclosure_timeline,omitempty"`
	PGPKey []string `json:"pgp_key,omitempty"`
	Hiring []string `json:"hiring,omitempty"`
	SecuritytxtURL []string `json:"securitytxt_url,omitempty"`
	PreferredLanguages string `json:"preferred_languages,omitempty"`
}

func FromSecurityTxt(txt *securitytxt.SecurityTxt) *Fields {
	f := &Fields{
		ProgramName: txt.Domain,
		PolicyURL: txt.Policy,
		ContactURL: txt.Contact,
		HallOfFame: txt.Acknowledgments,
		PGPKey: txt.Encryption,
		Hiring: txt.Hiring,
		SecuritytxtURL: txt.Canonical,
		PreferredLanguages: txt.PreferredLanguages,
	}

	return f
}
