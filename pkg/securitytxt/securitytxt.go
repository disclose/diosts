package securitytxt

import (
	"fmt"
	"time"
)

// https://tools.ietf.org/html/draft-foudil-securitytxt-09#section-3.5
// Note: we don't use the format tag yet.
type SecurityTxt struct {
	// Official fields
	Acknowledgments []string `format:"secure-url"`
	Canonical []string `format:"secure-url"`
	Contact []string `format:"contact-uri"`
	Encryption []string `format:"key-uri"`
	Expires time.Time
	Hiring []string `format:"secure-url"`
	Policy []string `format:"secure-url"`
	PreferredLanguages string `format:"rfc5646"`

	// Other useful fields
	Domain string
	RetrievedFrom string

	// TODO: Verify signature and store signing key
	signed bool

	// Collection of errors of this security.txt that did not prohibit
	// us from parsing at least something
	errors []error
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

func (t *SecurityTxt) AssignField(field *Field) (errMsg string) {
	// I've thought about doing this by automatically finding the right
	// fields in the SecurityTxt struct with reflect, but there's no
	// need to be that flexible, it's slower and it also hurts my head.

	if field.Value == "" {
		return emptyValueErrorMsg
	}

	// fieldName is lower case
	switch field.Key {
	case "acknowledgments":
		return assignListValue(&t.Acknowledgments, field)
	case "acknowledgements":
		assignListValue(&t.Acknowledgments, field)
		return acknowledgmentsErrorMsg
	case "canonical":
		return assignListValue(&t.Canonical, field)
	case "contact":
		return assignListValue(&t.Contact, field)
	case "encryption":
		return assignListValue(&t.Encryption, field)
	case "expires":
		return assignTimeValue(&t.Expires, field)
	case "hiring":
		return assignListValue(&t.Hiring, field)
	case "policy":
		return assignListValue(&t.Policy, field)
	case "preferred-languages":
		return assignStringValue(&t.PreferredLanguages, field)
	default:
		return fmt.Sprintf(unknownFieldErrorMsg, field.Key)
	}
}

// TODO: Deeper verification to check if everything is exactly to spec
func (t *SecurityTxt) Validate() error {
	//  The "Contact" field MUST always be present in a security.txt file.
	if len(t.Contact) == 0 {
		return fmt.Errorf(missingContactErrorMsg)
	}

	return nil
}

func (t *SecurityTxt) ParseErrors() []error {
	return t.errors
}

func (t *SecurityTxt) addError(lineNo int, line, msg string) {
	t.errors = append(t.errors, SyntaxError{
		lineNo: lineNo,
		line: line,
		msg: msg,
	})
}

func (t *SecurityTxt) addHTTPError(err error) {
	t.errors = append(t.errors, HTTPError{err})
}
