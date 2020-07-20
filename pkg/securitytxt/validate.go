package securitytxt

type ValidateFunc func(string) error

var Validators = map[string]ValidateFunc{
	"secure-url": ValidateSecureURL,
	"contact-uri": ValidateContactURI,
	"key-uri": ValidateKeyURI,
	"rfc5646": ValidateRFC5646,
}

func ValidateSecureURL(in string) error {
	return nil
}

func ValidateContactURI(in string) error {
	return nil
}

func ValidateKeyURI(in string) error {
	return nil
}

func ValidateRFC5646(in string) error {
	return nil
}
