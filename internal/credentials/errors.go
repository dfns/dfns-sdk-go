package credentials

import "fmt"

// NotAllowedCredentialsError indicates that the provided credential ID
// is not among the allowed credentials.
type NotAllowedCredentialsError struct {
	CredID       string
	AllowedCreds []AllowCredential
}

// Error returns the error message.
func (e *NotAllowedCredentialsError) Error() string {
	return fmt.Sprintf("%s does not match allowed credentials: %v", e.CredID, e.AllowedCreds)
}
