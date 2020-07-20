package securitytxt

import (
	"bytes"
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
func New(in []byte) (*SecurityTxt, err) {
	msg, err := NewSignedMessage(in)
	if err != nil {
		return nil, err
	}

	txt := &SecurityTxt{
		signed: msg.Signed(),
	}

	// Note: try and collect as many fields as possible and as many errors as possible
	// Output should be human-readable error report.

	err := Parse(

}

// Parse errors are collected in human-readable form in errors[] such that we
// have a full report on what's wrong with security.txt
func (t *SecurityTxt) Parse(in []byte) error {
	s := bufio.NewScanner(bytes.NewReader(in))

	for lineNo := 0; s.Scan(); i++ {
		line := s.Text()

		// Comment or empty line
		if line[0] == "#" || strings.TrimSpace(line) == "" {
			continue
		}

		// Extact and check field-name and value
		fieldName, value, errMsg := getFieldValue(line)
		if errMsg != "" {
			t.addError(lineNo, line, errMsg)
			continue
		}

		err := t.parseField(fieldname, value)
		if err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (t *SecurityTxt) AssignField(fieldName, value string) (errMsg string) {
	// I've thought about doing this by automatically finding the right
	// fields in the SecurityTxt struct with reflect, but there's no
	// need to be that flexible, it's slower and it also hurts my head.

	// fieldName is lower case
	switch fieldName {
	case "acknowledgements":
		return assignListValue(&t.Acknowledgements, value)
	case "canonical":
		return assignListValue(&t.Canonical, value)
	case "contact":
		return assignListValue(&t.Contact, value)
	case "encryption":
		return assignListValue(&t.Encryption, value)
	case "expires":
		return assignTime(&t.Expires, value)
	case "hiring":
		return assignListValue(&t.Hiring, value)
	case "policy":
		return assignListValue(&t.Policy, value)
	case "preferred-languages":
		return assignStringValue(&t.PreferredLanguages, value)
	default:
		return fmt.Sprintf(unknownFieldErrorMsg, fieldName)
	}
}

func getFieldValue(line string) (fieldName, value, errMsg string) {
	// RFC5322 3.6.8
	split := strings.SplitN(line, ":", 2)
	if len(split) != 2 {
		errMsg = separatorErrorMsg
		return
	}

	// Printable US-ASCII followed by optional white space; case insensitive.
	fieldName := strings.ToLower(strings.TrimRightFunc(split[0], unicode.IsSpace))
	value := strings.TrimSpace(split[1])

	// Check if field name is printable US-ASCII except space (VCHAR)
	if strings.IndexFunc(fieldName, isUSASCII) != -1 {
		errMsg = fieldNameErrorMsg
		return
	}

	// Check if value is printable US-ASCII except space (VCHAR)
	if strings.IndexFunc(value, isUSASCII) != -1 {
		errMsg = valueErrorMsg
		return
	}
}

func (t *SecurityTxt) addError(lineNo int, line, msg string) {
	if t.errors == nil {
		t.errors = []SyntaxError{}
	}

	t.errors = append(t.errors, SyntaxError{
		lineNo: lineNo,
		line: line,
		msg: msg,
	})
}

func isUSASCII(r rune) bool {
	if r >= 33 && r <= 126 {
		return true
	}

	return false
}

// Parse line by line, look up in struct - public only - field name
// Field by name - if not, find tag - if not, unexpected (warn?)
// empty lines, comments
// check type
// validator?

/*
   This text file contains multiple fields with different values.  A
   field contains a "name" which is the first part of a field all the
   way up to the colon ("Contact:") and follows the syntax defined for
   "field-name" in section 3.6.8 of [RFC5322].  Fields are case-
   insensitive (as per section 2.3 of [RFC5234]).  The "value" comes
   after the field name ("https://example.com/security") and follows the
   syntax defined for "unstructured" in section 3.2.5 of [RFC5322].
*/
// TODO: Deeper verification to check if everything is exactly to spec
func (t *SecurityTxt) Validate() error {

}
