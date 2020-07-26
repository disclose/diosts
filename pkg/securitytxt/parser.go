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
		fieldName, value, errMsg := getFieldValue(line)
		if errMsg != "" {
			txt.addError(lineNo, line, errMsg)
			continue
		}

		errMsg = txt.AssignField(fieldName, value)
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

func getFieldValue(line string) (fieldName, value, errMsg string) {
	// RFC5322 3.6.8
	split := strings.SplitN(line, ":", 2)
	if len(split) != 2 {
		errMsg = separatorErrorMsg
		return
	}

	// Printable US-ASCII followed by optional white space; case insensitive.
	fieldName = strings.ToLower(strings.TrimRightFunc(split[0], unicode.IsSpace))
	value = strings.TrimSpace(split[1])

	// Check if field name is printable US-ASCII except space (VCHAR)
	if strings.IndexFunc(fieldName, isNotUSASCII) != -1 {
		errMsg = fieldNameErrorMsg
		return
	}

	// Check if value is printable US-ASCII except space (VCHAR)
	if strings.IndexFunc(value, isNotUSASCII) != -1 {
		errMsg = valueErrorMsg
		return
	}

	return
}

func isNotUSASCII(r rune) bool {
	if r < 33 || r > 126 {
		return true
	}

	return false
}

func assignListValue(fieldName string, list *[]string, value string) (errMsg string) {
	*list = append(*list, value)
	return
}

func assignStringValue(fieldName string, str *string, value string) (errMsg string) {
	if *str != "" {
		return fmt.Sprintf(multipleValueErrorMsg, fieldName)
	}

	*str = value
	return
}

func assignTimeValue(fieldName string, t *time.Time, value string) (errMsg string) {
	if !t.IsZero() {
		return fmt.Sprintf(multipleValueErrorMsg, fieldName)
	}

	var err error

	// Check if we start with day number, else assume day name
	if unicode.IsDigit(rune(value[0])) {
		// "02 Jan 06 15:04 -0700"
		*t, err = time.Parse(time.RFC822Z, value)
	} else {
		// "Mon, 02 Jan 2006 15:04:05 -0700" 
		*t, err = time.Parse(time.RFC1123Z, value)
	}

	if err != nil {
		return fmt.Sprintf(invalidTimeErrorMsg, fieldName, err.Error())
	}
	return
}
