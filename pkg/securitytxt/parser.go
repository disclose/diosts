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
		Key:   strings.ToLower(strings.TrimRightFunc(split[0], unicode.IsSpace)),
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

	value := field.Value

	// Try parsing in various formats as specified in RFC 9116
	// ISO 8601 / RFC 3339 format is commonly used for Expires field
	formats := []string{
		time.RFC3339,               // "2006-01-02T15:04:05Z07:00" - ISO 8601 / RFC 3339
		time.RFC1123Z,              // "Mon, 02 Jan 2006 15:04:05 -0700" - RFC 5322 with numeric zone
		time.RFC1123,               // "Mon, 02 Jan 2006 15:04:05 MST" - RFC 5322
		time.RFC822Z,               // "02 Jan 06 15:04 -0700" - RFC 5322 with numeric zone
		time.RFC822,                // "02 Jan 06 15:04 MST" - RFC 5322
		"2006-01-02T15:04:05Z",     // ISO 8601 without timezone offset
		"2006-01-02T15:04:05.000Z", // ISO 8601 with milliseconds
		"2006-01-02",               // Simple date format
	}

	var lastErr error
	for _, format := range formats {
		parsed, parseErr := time.Parse(format, value)
		if parseErr == nil {
			*t = parsed
			return nil
		}
		lastErr = parseErr
	}

	// If all parsing attempts failed
	return NewInvalidTimeError(field, lastErr)
}
