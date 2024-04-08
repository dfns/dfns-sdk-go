package dfnsapiclient

import (
	"reflect"
	"testing"
)

// TestNewDfnsAPIOptions tests the NewDfnsAPIOptions function.
func TestNewDfnsAPIOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         *DfnsAPIConfig
		expectedResult *DfnsAPIOptions
		expectedError  error
	}{
		{
			name: "ValidConfig",
			config: &DfnsAPIConfig{
				AppID:   "testAppID",
				BaseURL: "https://example.com/api",
			},
			expectedResult: &DfnsAPIOptions{
				DfnsAPIConfig: &DfnsAPIConfig{
					AppID:   "testAppID",
					BaseURL: "https://example.com/api",
				},
			},
			expectedError: nil,
		},
		{
			name:           "EmptyAppID",
			config:         &DfnsAPIConfig{},
			expectedResult: nil,
			expectedError:  ErrAppIDEmpty,
		},
		{
			name: "EmptyBaseURL",
			config: &DfnsAPIConfig{
				AppID: "testAppID",
			},
			expectedResult: nil,
			expectedError:  ErrBaseURLEmpty,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := NewDfnsAPIOptions(test.config, nil)
			if err != test.expectedError {
				t.Errorf("Unexpected error. Got: %v, Want: %v", err, test.expectedError)
			}

			if test.expectedResult == nil && result != nil {
				t.Error("Expected nil result")
			}

			if test.expectedResult != nil && result == nil {
				t.Error("Expected non-nil result")
			}

			if test.expectedResult != nil && result != nil {
				if !reflect.DeepEqual(*test.expectedResult, *result) {
					t.Errorf("Result mismatch. Got: %v, Want: %v", result, test.expectedResult)
				}
			}
		})
	}
}
