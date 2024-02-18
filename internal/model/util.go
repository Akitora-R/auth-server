package model

import (
	"database/sql/driver"
	"encoding/json"
)

type TextArray []string

func (j *TextArray) Value() (driver.Value, error) {
	return json.Marshal(j)
}

func (j *TextArray) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal(bytes, &j)
	}

	return json.Unmarshal(bytes, j)
}
