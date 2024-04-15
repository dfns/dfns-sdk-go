package dfnsapiclient

import (
	"reflect"
	"testing"

	"github.com/dfns/dfns-sdk-go/internal/dfnsapiclient"
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
			expectedError:  errAppIDEmpty,
		},
		{
			name: "EmptyBaseURL",
			config: &DfnsAPIConfig{
				AppID: "testAppID",
			},
			expectedResult: nil,
			expectedError:  errBaseURLEmpty,
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

func TestCreateDfnsAPIClient(t *testing.T) {
	t.Parallel()

	options, err := NewDfnsAPIOptions(&DfnsAPIConfig{
		AppID:     "your_app_id",
		AuthToken: func(s string) *string { return &s }("authToken"),
		BaseURL:   "https://yourapi.example.com",
	}, nil)
	if err != nil {
		t.Fatal("error when creating DfnsAPIOptions")
	}

	client := CreateDfnsAPIClient(options)

	if client.Transport == nil {
		t.Fatal("Client transport is nil")
	}

	_, ok := client.Transport.(*dfnsapiclient.AuthTransport)
	if !ok {
		t.Fatal("Expected dfnsapi.AuthTransport got different type")
	}
}
