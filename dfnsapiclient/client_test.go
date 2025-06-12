package dfnsapiclient

import (
	"errors"
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
				OrgID:   "testOrgID",
				BaseURL: "https://example.com/api",
			},
			expectedResult: &DfnsAPIOptions{
				DfnsAPIConfig: &DfnsAPIConfig{
					OrgID:   "testOrgID",
					BaseURL: "https://example.com/api",
				},
			},
			expectedError: nil,
		},
		{
			name:           "EmptyOrgID",
			config:         &DfnsAPIConfig{},
			expectedResult: nil,
			expectedError:  errOrgIDEmpty,
		},
		{
			name: "EmptyBaseURL",
			config: &DfnsAPIConfig{
				OrgID: "testOrgID",
			},
			expectedResult: nil,
			expectedError:  errBaseURLEmpty,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := NewDfnsAPIOptions(test.config, nil)
			if !errors.Is(err, test.expectedError) {
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
		OrgID:     "your_org_id",
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
