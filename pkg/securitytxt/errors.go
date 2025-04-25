package securitytxt

import (
	"errors"
	"fmt"
)

const SECURITYTXTSPEC = "RFC 9116"

// Wrap error with some context
type SyntaxError struct {
	lineNo int
	line   string
	err    error
}

func (e SyntaxError) Error() string {
	return fmt.Sprintf("Error in line %d: %s", e.lineNo, e.err.Error())
}

func (e SyntaxError) Unwrap() error {
	return e.err
}

// Generic error wrapper to make other error types with
type ErrorWrapper struct {
	err error
}

func (e ErrorWrapper) Error() string {
	return e.err.Error()
}

func (e ErrorWrapper) Unwrap() error {
	return e.err
}

// Errors during parsing - basic structure of security.txt is incorrect
var (
	AcknowledgmentsError = errors.New("invalid field name 'acknowledgements', should be 'acknowledgments' as per section 3.5.1 of " + SECURITYTXTSPEC)
	EmptyValueError      = errors.New("value cannot be empty")
	FieldNameError       = errors.New("field-name should be printable US-ASCII except space and :, as per section 3.6.8 of RFC5322")
	SeparatorError       = errors.New("no ':' found to separate field-name and value, as per section 3.6.8 of RFC5322")
	ValueError           = errors.New("value should be printable US-ASCII except space, as per 'unstructured' syntax in section 3.2.5 of RFC5322")
)

func NewAcknowledgmentsError() ParseError { return NewParseError(AcknowledgmentsError) }
func NewEmptyValueError() ParseError      { return NewParseError(EmptyValueError) }
func NewFieldNameError() ParseError       { return NewParseError(FieldNameError) }
func NewSeparatorError() ParseError       { return NewParseError(SeparatorError) }
func NewValueError() ParseError           { return NewParseError(ValueError) }

type ParseError struct {
	ErrorWrapper
}

func NewParseError(err error) ParseError {
	return ParseError{ErrorWrapper{err}}
}

// Validation errors
var (
	MissingContactError = errors.New("Mandatory field 'Contact' not present as per section 2.5.3 of " + SECURITYTXTSPEC)
	MissingExpiresError = errors.New("Mandatory field 'Expires' not present as per section 2.5.5 of " + SECURITYTXTSPEC)
	ExpiredError        = errors.New("The security.txt file has expired as per section 2.5.5 of " + SECURITYTXTSPEC)
)

func NewMissingContactError() ValidationError { return NewValidationError(MissingContactError) }
func NewMissingExpiresError() ValidationError { return NewValidationError(MissingExpiresError) }
func NewExpiredError() ValidationError        { return NewValidationError(ExpiredError) }

type ValidationError struct {
	ErrorWrapper
}

func NewValidationError(err error) ValidationError {
	return ValidationError{ErrorWrapper{err}}
}

// Errors during HTTP retrieval
const (
	contentTypeErrorMsg = "invalid Content-Type of '%s', expecting 'text/plain; charset=utf-8' as per section 3 of " + SECURITYTXTSPEC
	redirectErrorMsg    = "redirect from %s to %s, prohibiting redirect to different hostname"
)

type ContentTypeError struct {
	contentType string
}

func NewContentTypeError(contentType string) HTTPError {
	return NewHTTPError(ContentTypeError{contentType})
}

func (e ContentTypeError) Error() string {
	return fmt.Sprintf(contentTypeErrorMsg, e.contentType)
}

type RedirectError struct {
	from, to string
}

func NewRedirectError(from, to string) HTTPError {
	return NewHTTPError(RedirectError{from, to})
}

func (e RedirectError) Error() string {
	return fmt.Sprintf(redirectErrorMsg, e.from, e.to)
}

type HTTPError struct {
	ErrorWrapper
}

func NewHTTPError(err error) HTTPError {
	return HTTPError{ErrorWrapper{err}}
}

// Errors with field names or values
const (
	invalidTimeErrorMsg   = "invalid time in field '%s' according to section 3.3 of RFC5322"
	multipleValueErrorMsg = "multiple values for field '%s', expecting one value as per section 3.5 of " + SECURITYTXTSPEC
	unknownFieldErrorMsg  = "unexpected field-name '%s', as per section 3.5 of " + SECURITYTXTSPEC
)

func NewInvalidTimeError(f *Field, err error) FieldError {
	return FieldError{
		field: f,
		msg:   invalidTimeErrorMsg,
		err:   err,
	}
}

func NewMultipleValueError(f *Field) FieldError {
	return FieldError{
		field: f,
		msg:   multipleValueErrorMsg,
		err:   nil,
	}
}

func NewUnknownFieldError(f *Field) FieldError {
	return FieldError{
		field: f,
		msg:   unknownFieldErrorMsg,
		err:   nil,
	}
}

type FieldError struct {
	field *Field
	msg   string
	err   error
}

func (e FieldError) Error() string {
	if e.err != nil {
		return fmt.Sprintf(e.msg, e.field.Key) + ": " + e.err.Error()
	}
	return fmt.Sprintf(e.msg, e.field.Key)
}
