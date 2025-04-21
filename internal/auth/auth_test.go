package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		name   string
		input  http.Header
		output string
		err    error
	}
	tests := []test{
		{
			name:   "No auth header",
			input:  http.Header{},
			output: "",
			err:    ErrNoAuthHeaderIncluded,
		},
		{
			name:   "Bearer token",
			input:  http.Header{"Authorization": []string{"Bearer sometoken"}},
			output: "",
			err:    errors.New("malformed authorization header"),
		},
		{
			name:   "No apiKey value",
			input:  http.Header{"Authorization": []string{"ApiKey"}},
			output: "",
			err:    errors.New("malformed authorization header"),
		},
		{
			name:   "Valid key",
			input:  http.Header{"Authorization": []string{"ApiKey secret-api-key"}},
			output: "secret-api-key",
			err:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, gotErr := GetAPIKey(tc.input)

			// Compare string output
			if got != tc.output {
				t.Errorf("expected output: %q, got: %q", tc.output, got)
			}

			// Compare error
			if tc.err == nil && gotErr != nil {
				t.Errorf("expected no error, got: %v", gotErr)
			} else if tc.err != nil && (gotErr == nil || gotErr.Error() != tc.err.Error()) {
				t.Errorf("expected error: %v, got: %v", tc.err, gotErr)
			}
		})
	}
}
