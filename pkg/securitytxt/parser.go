package securitytxt

import (
	"bufio"
	"bytes"
	"fmt"
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
		field, errMsg := getFieldValue(line)
		if errMsg != "" {
			txt.addError(lineNo, line, errMsg)
			continue
		}

		errMsg = txt.AssignField(field)
		if errMsg != "" {
			txt.addError(lineNo, line, errMsg)
			continue
		}
	}

	if err := s.Err(); err != nil {
		return err
	}

	return nil
}

func getFieldValue(line string) (*Field, string) {
	// RFC5322 3.6.8
	split := strings.SplitN(line, ":", 2)
	if len(split) != 2 {
		return nil, separatorErrorMsg
	}

	// Printable US-ASCII followed by optional white space; case insensitive.
	field := &Field{
		Key: strings.ToLower(strings.TrimRightFunc(split[0], unicode.IsSpace)),
		Value: strings.TrimSpace(split[1]),
	}

	// Check if field name is printable US-ASCII except space (VCHAR)
	if strings.IndexFunc(field.Key, isNotUSASCII) != -1 {
		return field, fieldNameErrorMsg
	}

	// Check if value is printable US-ASCII except space (VCHAR)
	if strings.IndexFunc(field.Value, isNotUSASCII) != -1 {
		return field, valueErrorMsg
	}

	return nil, ""
}

func isNotUSASCII(r rune) bool {
	if r < 33 || r > 126 {
		return true
	}

	return false
}

func assignListValue(list *[]string, field *Field) (errMsg string) {
	*list = append(*list, field.Value)
	return
}

func assignStringValue(str *string, field *Field) (errMsg string) {
	if *str != "" {
		return fmt.Sprintf(multipleValueErrorMsg, field.Key)
	}

	*str = field.Value
	return
}

func assignTimeValue(t *time.Time, field *Field) (errMsg string) {
	if !t.IsZero() {
		return fmt.Sprintf(multipleValueErrorMsg, field.Key)
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
		return fmt.Sprintf(invalidTimeErrorMsg, field.Key, err.Error())
	}
	return
}
