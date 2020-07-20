package securitytxt

import (
	"fmt"
)

const (
	separatorErrorMsg = "no ':' found to separate field-name and value, as per section 3.6.8 of RFC5322"
	fieldNameErrorMsg = "field-name should be printable US-ASCII except space and :, as per section 3.6.8 of RFC5322"
	valueErrorMsg = "value should be printable US-ASCII except space, as per 'unstructured' syntax in section 3.2.5 of RFC5322"
	unknownFieldErrorMsg = "unexpected field-name '%s', as per section 3.5 of draft-foudil-securitytxt-09"
)

type SyntaxError struct {
	lineNo int
	line string
	msg string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("Error in line %d: %s", lineNo, msg)
}

