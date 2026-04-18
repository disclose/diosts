package securitytxt

import (
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
)

type ValidateFunc func(string) error

var Validators = map[string]ValidateFunc{
	"secure-url":  ValidateSecureURL,
	"contact-uri": ValidateContactURI,
	"key-uri":     ValidateKeyURI,
	"rfc5646":     ValidateRFC5646,
}

var rfc5646Pattern = regexp.MustCompile(`^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$`)

func ValidateSecureURL(in string) error {
	parsed, err := validateAbsoluteURI(in)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("must use https")
	}
	if parsed.Host == "" {
		return fmt.Errorf("missing host")
	}
	return nil
}

func ValidateContactURI(in string) error {
	parsed, err := validateAbsoluteURI(in)
	if err != nil {
		return err
	}

	switch parsed.Scheme {
	case "https":
		if parsed.Host == "" {
			return fmt.Errorf("missing host")
		}
	case "mailto":
		address := parsed.Opaque
		if address == "" {
			address = strings.TrimPrefix(parsed.Path, "/")
		}
		if address == "" {
			return fmt.Errorf("missing email address")
		}
		if _, err := mail.ParseAddress(address); err != nil {
			return fmt.Errorf("invalid email address")
		}
	default:
		// Allow other absolute URI schemes, but still require a meaningful target.
		if parsed.Host == "" && parsed.Opaque == "" && parsed.Path == "" {
			return fmt.Errorf("missing target")
		}
	}

	return nil
}

func ValidateKeyURI(in string) error {
	parsed, err := validateAbsoluteURI(in)
	if err != nil {
		return err
	}
	if parsed.Host == "" && parsed.Opaque == "" && parsed.Path == "" {
		return fmt.Errorf("missing target")
	}
	return nil
}

func ValidateRFC5646(in string) error {
	for _, tag := range strings.Split(in, ",") {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			return fmt.Errorf("contains an empty language tag")
		}
		if !rfc5646Pattern.MatchString(tag) {
			return fmt.Errorf("contains invalid language tag %q", tag)
		}
	}
	return nil
}

func validateAbsoluteURI(in string) (*url.URL, error) {
	if strings.TrimSpace(in) != in {
		return nil, fmt.Errorf("unexpected surrounding whitespace")
	}

	parsed, err := url.Parse(in)
	if err != nil {
		return nil, fmt.Errorf("invalid URI")
	}
	if parsed.Scheme == "" {
		return nil, fmt.Errorf("missing URI scheme")
	}

	return parsed, nil
}
