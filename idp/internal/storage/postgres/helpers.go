package postgres

import (
	"encoding/json"
	"fmt"
)

// marshalJSON converts a Go value to JSONB-compatible bytes
func marshalJSON(v interface{}) ([]byte, error) {
	if v == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(v)
}

// unmarshalJSON converts JSONB bytes to a Go value
func unmarshalJSON(data []byte, v interface{}) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}

// unmarshalStringArray converts JSONB bytes to string slice
func unmarshalStringArray(data []byte) []string {
	var result []string
	if err := unmarshalJSON(data, &result); err != nil {
		return []string{}
	}
	return result
}

// extractClientIDFromSerialized extracts client ID from serialized request data
func extractClientIDFromSerialized(data []byte) (string, error) {
	var req struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return "", fmt.Errorf("failed to extract client ID: %w", err)
	}
	return req.ClientID, nil
}
