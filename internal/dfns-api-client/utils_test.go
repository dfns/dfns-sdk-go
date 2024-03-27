package dfns_api_client

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGenerateNonce(t *testing.T) {
	t.Parallel()

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
	err = json.Unmarshal(decodedData, &data)
	if err != nil {
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

func TestGetCurrentTime(t *testing.T) {
	t.Parallel()

	now := time.Now()

	currentTime := getCurrentTime()

	// Define a tolerance window
	tolerance := time.Second

	if currentTime.Before(now.Add(-tolerance)) || currentTime.After(now.Add(tolerance)) {
		t.Errorf("getCurrentTime returned a time not within the tolerance window around the current time. Got: %s, Expected: %s ± %s", currentTime, now, tolerance)
	}
}

func TestGenerateUUID(t *testing.T) {
	t.Parallel()

	generatedUUID := generateUUID()

	_, err := uuid.Parse(generatedUUID)
	if err != nil {
		t.Errorf("generatedUUID generated a non parsable uuid: %s", generatedUUID)
	}
}
