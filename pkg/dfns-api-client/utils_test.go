package dfns_api_client

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGenerateNonce(t *testing.T) {
	// Mock the UUID generation
	generateUUID = func() string { return "mock-uuid" }
	defer func() { generateUUID = uuid.NewString }() // Restore the original function

	// Mock the time
	mockTime := time.Date(2024, time.February, 15, 10, 0, 0, 0, time.UTC)
	getCurrentTime = func() time.Time { return mockTime }
	defer func() { getCurrentTime = time.Now }() // Restore the original function

	// Call the function
	nonce := generateNonce()

	// Decode the generated nonce
	decodedData, err := base64.URLEncoding.DecodeString(nonce)
	assert.NoError(t, err)

	// Unmarshal the decoded data
	var data map[string]interface{}
	err = json.Unmarshal(decodedData, &data)
	assert.NoError(t, err)

	// Check if the UUID and date are correct
	assert.Equal(t, "mock-uuid", data["uuid"])
	assert.Equal(t, "2024-02-15T10:00:00Z", data["date"])
}
