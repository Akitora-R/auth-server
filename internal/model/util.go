package model

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

type TextArray []string

// Value implements driver.Valuer converting Go []string to PostgreSQL text[] literal
func (j TextArray) Value() (driver.Value, error) {
	if j == nil {
		return "{}", nil
	}
	parts := make([]string, 0, len(j))
	for _, s := range j {
		esc := strings.ReplaceAll(s, `\\`, `\\\\`)
		esc = strings.ReplaceAll(esc, `"`, `\\"`)
		parts = append(parts, `"`+esc+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}", nil
}

// Scan implements sql.Scanner parsing PostgreSQL text[] into []string
func (j *TextArray) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	s, ok := value.(string)
	if !ok {
		b, ok2 := value.([]byte)
		if !ok2 {
			return fmt.Errorf("cannot convert %T to TextArray", value)
		}
		s = string(b)
	}
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return fmt.Errorf("invalid PostgreSQL array format: %s", s)
	}
	inner := s[1 : len(s)-1]
	if inner == "" {
		*j = []string{}
		return nil
	}
	// Simple split by comma; handles quoted elements with escaped quotes
	var elems []string
	cur := ""
	inQuotes := false
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '"' {
			if inQuotes && i+1 < len(inner) && inner[i+1] == '"' { // escaped quote
				cur += "\""
				i++
				continue
			}
			inQuotes = !inQuotes
			continue
		}
		if c == ',' && !inQuotes {
			elems = append(elems, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		elems = append(elems, cur)
	}
	// Unescape
	for i, e := range elems {
		e = strings.ReplaceAll(e, `\\\"`, `"`)
		e = strings.ReplaceAll(e, `\\\\`, `\\`)
		elems[i] = e
	}
	*j = TextArray(elems)
	return nil
}
