package dfns_api_client

import (
	"testing"
)

func TestNewDfnsError(t *testing.T) {
	statut := 404
	message := "Not Found"
	context := map[string]interface{}{"key": "value"}

	err := NewDfnsError(statut, message, context)

	if err.HTTPStatus != statut {
		t.Errorf("Expected HTTPStatus to be %d, got %d", statut, err.HTTPStatus)
	}

	if err.Message != message {
		t.Errorf("Expected Message to be %q, got %q", message, err.Message)
	}

	if len(err.Context) != len(context) {
		t.Errorf("Expected Context length to be %d, got %d", len(context), len(err.Context))
	}
}

func TestDfnsError_Error(t *testing.T) {
	statut := 404
	message := "Not Found"
	context := map[string]interface{}{"key": "value"}

	err := NewDfnsError(statut, message, context)

	expectedErrorJSON := `{
  "httpStatus": 404,
  "message": "Not Found",
  "context": {
    "key": "value"
  }
}`

	if err.Error() != expectedErrorJSON {
		t.Errorf("Expected Error() output to be %q, got %q", expectedErrorJSON, err.Error())
	}
}

func TestNewPolicyPendingError(t *testing.T) {
	context := map[string]interface{}{"key": "value"}

	err := NewPolicyPendingError(context)

	if err.HTTPStatus != PolicyPendingErrorCode {
		t.Errorf("Expected HTTPStatus to be %d, got %d", PolicyPendingErrorCode, err.HTTPStatus)
	}

	expectedMessage := "Operation triggered a policy pending approval"
	if err.Message != expectedMessage {
		t.Errorf("Expected Message to be %q, got %q", expectedMessage, err.Message)
	}

	if len(err.Context) != len(context) {
		t.Errorf("Expected Context length to be %d, got %d", len(context), len(err.Context))
	}
}

func TestPolicyPendingError_Error(t *testing.T) {
	context := map[string]interface{}{"key": "value"}

	err := NewPolicyPendingError(context)

	expectedErrorJSON := `{
  "httpStatus": 202,
  "message": "Operation triggered a policy pending approval",
  "context": {
    "key": "value"
  }
}`

	if err.Error() != expectedErrorJSON {
		t.Errorf("Expected Error() output to be %q, got %q", expectedErrorJSON, err.Error())
	}
}

func TestDfnsError_Error_MarshalError(t *testing.T) {
	// Create a DfnsError with nil error
	err := &DfnsError{
		HTTPStatus: 404,
		Message:    "Not Found",
		Context:    map[string]interface{}{"toto": make(chan int)},
	}

	errorMsg := err.Error()

	expectedErrorMsg := "DFNS-ERROR: Not Found (status code: 404)"
	if errorMsg != expectedErrorMsg {
		t.Errorf("Expected error message %q, got %q", expectedErrorMsg, errorMsg)
	}
}
