package dfnsapiclient

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

//nolint:paralleltest // generateUUID is modified in other functions
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
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal the decoded data
	var data map[string]interface{}
	if err := json.Unmarshal(decodedData, &data); err != nil {
		t.Fatal(err)
	}

	// Check if the UUID and date are correct
	if data["uuid"] != "mock-uuid" {
		t.Errorf("expected UUID: mock-uuid, got: %s", data["uuid"])
	}

	if data["date"] != "2024-02-15T10:00:00Z" {
		t.Errorf("expected date: 2024-02-15T10:00:00Z, got: %s", data["date"])
	}
}
