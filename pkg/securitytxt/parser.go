package securitytxt

import (
	"bufio"
	"bytes"
	"strings"
	"time"
	"unicode"
)

// Parse errors are collected in human-readable form in errors[] such that we
// have a full report on what's wrong with security.txt
func Parse(in []byte, txt *SecurityTxt) error {
	s := bufio.NewScanner(bytes.NewReader(in))

	for lineNo := 0; s.Scan(); lineNo++ {
		line := s.Text()

		// Comment or empty line
		if strings.TrimSpace(line) == "" || line[0] == '#' {
			continue
		}

		// Extact and check field-name and value
		field, err := getFieldValue(line)
		if err != nil {
			// We bail out on parse errors - this could very well
			// be a 404 page
			return err
		}

		if err := txt.AssignField(field); err != nil {
			txt.addSyntaxError(lineNo, line, err)
			continue
		}
	}

	if err := s.Err(); err != nil {
		return err
	}

	return nil
}

func getFieldValue(line string) (*Field, error) {
	// RFC5322 3.6.8
	split := strings.SplitN(line, ":", 2)
	if len(split) != 2 {
		return nil, NewSeparatorError()
	}

	// Printable US-ASCII followed by optional white space; case insensitive.
	field := &Field{
		Key: strings.ToLower(strings.TrimRightFunc(split[0], unicode.IsSpace)),
		Value: strings.TrimSpace(split[1]),
	}

	// Check if field name is printable US-ASCII except space (VCHAR)
	if strings.IndexFunc(field.Key, isNotUSASCII) != -1 {
		return field, NewFieldNameError()
	}

	// Check if value is printable US-ASCII except space (VCHAR)
	if strings.IndexFunc(field.Value, isNotUSASCII) != -1 {
		return field, NewValueError()
	}

	return field, nil
}

func isNotUSASCII(r rune) bool {
	if r < 33 || r > 126 {
		return true
	}

	return false
}

func assignListValue(list *[]string, field *Field) error {
	*list = append(*list, field.Value)
	return nil
}

func assignStringValue(str *string, field *Field) error {
	if *str != "" {
		return NewMultipleValueError(field)
	}

	*str = field.Value
	return nil
}

func assignTimeValue(t *time.Time, field *Field) error {
	if !t.IsZero() {
		return NewMultipleValueError(field)
	}

	var err error

	// Check if we start with day number, else assume day name
	if unicode.IsDigit(rune(field.Value[0])) {
		// "02 Jan 06 15:04 -0700"
		*t, err = time.Parse(time.RFC822Z, field.Value)
	} else {
		// "Mon, 02 Jan 2006 15:04:05 -0700" 
		*t, err = time.Parse(time.RFC1123Z, field.Value)
	}

	if err != nil {
		return NewInvalidTimeError(field, err)
	}
	return nil
}
