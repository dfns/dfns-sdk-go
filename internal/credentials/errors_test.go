package credentials

import (
	"fmt"
	"reflect"
	"testing"
)

func TestNotAllowedCredentialsError_Error(t *testing.T) {
	t.Parallel()

	allowedCreds := []AllowCredential{
		{ID: "allowed1", Type: "key", Transports: nil},
		{ID: "allowed2", Type: "key", Transports: nil},
	}

	err := &NotAllowedCredentialsError{
		CredID:       "testCred",
		AllowedCreds: allowedCreds,
	}

	expected := fmt.Sprintf("testCred does not match allowed credentials: %v", allowedCreds)
	if got := err.Error(); got != expected {
		t.Errorf("NotAllowedCredentialsError.Error() = %v, want %v", got, expected)
	}

	// Additionally ensure error implements error interface
	var _ error = err

	// Check that the underlying AllowedCreds value is as expected.
	if !reflect.DeepEqual(err.AllowedCreds, allowedCreds) {
		t.Errorf("Expected AllowedCreds %v, got %v", allowedCreds, err.AllowedCreds)
	}
}
