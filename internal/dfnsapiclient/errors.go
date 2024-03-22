package dfnsapiclient

import (
	"encoding/json"
	"fmt"
)

const PolicyPendingErrorCode = 202

// DfnsError represents an error that occurred during DFNS API requests.
type DfnsError struct {
	HTTPStatus int                    `json:"httpStatus"`        // HTTP status code
	Message    string                 `json:"message"`           // Error message
	Context    map[string]interface{} `json:"context,omitempty"` // Additional context
}

func NewDfnsError(statut int, message string, context map[string]interface{}) *DfnsError {
	return &DfnsError{
		HTTPStatus: statut,
		Message:    message,
		Context:    context,
	}
}

// Error returns the error message.
func (e *DfnsError) Error() string {
	// Return JSON representation of the error
	errJSON, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Sprintf("DFNS-ERROR: %s (status code: %d)", e.Message, e.HTTPStatus)
	}

	return string(errJSON)
}

// PolicyPendingError represents an error indicating that the operation triggered a policy pending approval.
type PolicyPendingError struct {
	DfnsError
}

// NewPolicyPendingError creates a new instance of PolicyPendingError.
func NewPolicyPendingError(context map[string]interface{}) *PolicyPendingError {
	return &PolicyPendingError{
		DfnsError: DfnsError{
			HTTPStatus: PolicyPendingErrorCode,
			Message:    "Operation triggered a policy pending approval",
			Context:    context,
		},
	}
}
