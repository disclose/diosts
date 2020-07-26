package securitytxt

import (
	"fmt"
	"time"
)

// https://tools.ietf.org/html/draft-foudil-securitytxt-09#section-3.5
type SecurityTxt struct {
	Acknowledgements []string `format:"secure-url"`
	Canonical []string `format:"secure-url"`
	Contact []string `format:"contact-uri"`
	Encryption []string `format:"key-uri"`
	Expires time.Time
	Hiring []string `format:"secure-url"`
	Policy []string `format:"secure-url"`
	PreferredLanguages string `format:"rfc5646"`

	// TODO: Verify signature and store signing key
	signed bool

	// Collection of errors of this security.txt that did not prohibit
	// us from parsing at least something
	errors []SyntaxError
}

// New extracts as many fields as possible and returns an error if there is
// a syntactical error, if the input is signed but the signature is incorrect
// or if the multiplicity of a field is not according to spec.
func New(in []byte) (*SecurityTxt, error) {
	msg, err := NewSignedMessage(in)
	if err != nil {
		return nil, err
	}

	txt := &SecurityTxt{
		signed: msg.Signed(),
	}

	// Note: try and collect as many fields as possible and as many errors as possible
	// Output should be human-readable error report.

	err = Parse(msg.Message(), txt)
	if err != nil {
		return nil, err
	}

	// Caller should deal with parsing errors
	return txt, nil
}

func (t *SecurityTxt) AssignField(fieldName, value string) (errMsg string) {
	// I've thought about doing this by automatically finding the right
	// fields in the SecurityTxt struct with reflect, but there's no
	// need to be that flexible, it's slower and it also hurts my head.

	if value == "" {
		return emptyValueErrorMsg
	}

	// fieldName is lower case
	switch fieldName {
	case "acknowledgements":
		return assignListValue(fieldName, &t.Acknowledgements, value)
	case "canonical":
		return assignListValue(fieldName, &t.Canonical, value)
	case "contact":
		return assignListValue(fieldName, &t.Contact, value)
	case "encryption":
		return assignListValue(fieldName, &t.Encryption, value)
	case "expires":
		return assignTimeValue(fieldName, &t.Expires, value)
	case "hiring":
		return assignListValue(fieldName, &t.Hiring, value)
	case "policy":
		return assignListValue(fieldName, &t.Policy, value)
	case "preferred-languages":
		return assignStringValue(fieldName, &t.PreferredLanguages, value)
	default:
		return fmt.Sprintf(unknownFieldErrorMsg, fieldName)
	}
}

// TODO: Deeper verification to check if everything is exactly to spec
func (t *SecurityTxt) Validate() error {
	return nil
}

func (t *SecurityTxt) ParseErrors() []SyntaxError {
	return t.errors
}

func (t *SecurityTxt) addError(lineNo int, line, msg string) {
	t.errors = append(t.errors, SyntaxError{
		lineNo: lineNo,
		line: line,
		msg: msg,
	})
}
