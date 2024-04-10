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
	originalGenerateUUID := generateUUID
	generateUUID = func() string { return "mock-uuid" }

	defer func() { generateUUID = originalGenerateUUID }() // Restore the original function

	// Mock the time
	mockTime := time.Date(2024, time.February, 15, 10, 0, 0, 0, time.UTC)

	originalGetCurrentTime := getCurrentTime
	getCurrentTime = func() time.Time { return mockTime }

	defer func() { getCurrentTime = originalGetCurrentTime }() // Restore the original function

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

//nolint:paralleltest // currentTime is modified in other functions
func TestGetCurrentTime(t *testing.T) {
	now := time.Now().UTC()

	currentTime := getCurrentTime()

	// Define a tolerance window
	tolerance := time.Second

	if currentTime.Before(now.Add(-tolerance)) || currentTime.After(now.Add(tolerance)) {
		t.Errorf("getCurrentTime returned a time not within the tolerance window around the current time. Got: %s, Expected: %s ± %s", currentTime, now, tolerance)
	}
}

//nolint:paralleltest // generatedUUID is modified in other functions
func TestGenerateUUID(t *testing.T) {
	generatedUUID := generateUUID()

	_, err := uuid.Parse(generatedUUID)
	if err != nil {
		t.Errorf("generatedUUID generated a non parsable uuid: %s", generatedUUID)
	}
}
