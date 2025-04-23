package securitytxt

import (
	"fmt"
	"time"
)

// https://www.rfc-editor.org/rfc/rfc9116
// Note: we don't use the format tag yet.
type SecurityTxt struct {
	// Official fields
	Acknowledgments    []string `format:"secure-url"`
	Canonical          []string `format:"secure-url"`
	Contact            []string `format:"contact-uri"`
	Encryption         []string `format:"key-uri"`
	Expires            time.Time
	Hiring             []string `format:"secure-url"`
	Policy             []string `format:"secure-url"`
	PreferredLanguages string   `format:"rfc5646"`

	// Other useful fields
	Domain        string
	RetrievedFrom string

	// RFC compliance tracking
	IsRFCCompliant   bool
	ComplianceIssues []string

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
		signed:         msg.Signed(),
		IsRFCCompliant: true, // Start with assuming compliance
	}

	// Note: try and collect as many fields as possible and as many errors as possible
	// Output should be human-readable error report.

	err = Parse(msg.Message(), txt)
	if err != nil {
		return nil, err
	}

	// Caller should deal with syntax errors
	return txt, nil
}

func (t *SecurityTxt) AssignField(field *Field) error {
	// I've thought about doing this by automatically finding the right
	// fields in the SecurityTxt struct with reflect, but there's no
	// need to be that flexible, it's slower and it also hurts my head.

	if field.Value == "" {
		return NewEmptyValueError()
	}

	// fieldName is lower case
	switch field.Key {
	case "acknowledgments":
		return assignListValue(&t.Acknowledgments, field)
	case "acknowledgements":
		assignListValue(&t.Acknowledgments, field)
		t.IsRFCCompliant = false
		t.ComplianceIssues = append(t.ComplianceIssues, "Using 'acknowledgements' instead of 'acknowledgments'")
		return NewAcknowledgmentsError()
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
		t.IsRFCCompliant = false
		t.ComplianceIssues = append(t.ComplianceIssues, "Contains unknown field: "+field.Key)
		return NewUnknownFieldError(field)
	}
}

// Validate checks if security.txt file adheres to RFC 9116
func (t *SecurityTxt) Validate() error {
	//  The "Contact" field MUST always be present in a security.txt file.
	if len(t.Contact) == 0 {
		t.IsRFCCompliant = false
		t.ComplianceIssues = append(t.ComplianceIssues, "Missing required 'Contact' field")
		return NewMissingContactError()
	}

	// Check if Expires field is present and valid
	if t.Expires.IsZero() {
		t.IsRFCCompliant = false
		t.ComplianceIssues = append(t.ComplianceIssues, "Missing required 'Expires' field")
		return NewMissingExpiresError()
	}

	// Check if Expires date is in the past
	if time.Now().After(t.Expires) {
		t.IsRFCCompliant = false
		t.ComplianceIssues = append(t.ComplianceIssues, "Expired security.txt file")
		return NewExpiredError()
	}

	return nil
}

func (t *SecurityTxt) ParseErrors() []error {
	return t.errors
}

func (t *SecurityTxt) addSyntaxError(lineNo int, line string, err error) {
	t.errors = append(t.errors, SyntaxError{
		lineNo: lineNo,
		line:   line,
		err:    err,
	})
	t.IsRFCCompliant = false
	t.ComplianceIssues = append(t.ComplianceIssues, fmt.Sprintf("Syntax error in line %d: %s", lineNo, err.Error()))
}

func (t *SecurityTxt) addError(err error) {
	t.errors = append(t.errors, err)
	t.IsRFCCompliant = false
	t.ComplianceIssues = append(t.ComplianceIssues, err.Error())
}
