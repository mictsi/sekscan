package batch

import (
	"bytes"
	"encoding/json"
)

// UnmarshalJSON retains input compatibility with old batch manifests without
// retaining or applying the removed Semgrep check to jobs or generated plans.
func (s *Settings) UnmarshalJSON(data []byte) error {
	type current Settings
	decoded := struct {
		*current
		Semgrep *bool `json:"semgrep"`
	}{current: (*current)(s)}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(&decoded)
}
