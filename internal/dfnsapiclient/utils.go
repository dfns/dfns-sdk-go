package dfnsapiclient

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

//nolint:gochecknoglobals // Can be mocked in tests
var generateUUID = func() string {
	return uuid.New().String()
}

//nolint:gochecknoglobals // Can be mocked in tests
var getCurrentTime = func() time.Time {
	return time.Now().UTC()
}

const JwtCustomDataClaim = "https://custom/app_metadata"

// Checks if the "orgId" claim in the auth token matches the provided orgId.
// Returns nil if it matches, otherwise returns an error.
func AssertAuthTokenIsSameOrg(authToken, orgID string) error {
	parts := strings.Split(authToken, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("failed to unmarshal JWT payload: %w", err)
	}

	customData, success := claims[JwtCustomDataClaim].(map[string]interface{})
	if !success {
		return errors.New("orgId claim not found in jwt token")
	}

	jwtOrgID, ok := customData["orgId"].(string)
	if !ok {
		return errors.New("orgId claim not found in jwt token")
	}

	if jwtOrgID != orgID {
		return fmt.Errorf("provided auth token is not scoped to org ID: expected %s, got %s", orgID, jwtOrgID)
	}

	return nil
}
