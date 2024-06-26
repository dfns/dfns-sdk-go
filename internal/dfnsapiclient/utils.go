package dfnsapiclient

import (
	"encoding/base64"
	"encoding/json"
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

// generateNonce generates a random nonce string.
func generateNonce() string {
	uuidStr := generateUUID()
	dateStr := getCurrentTime().Format(time.RFC3339)
	data := map[string]interface{}{
		"uuid": uuidStr,
		"date": dateStr,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return ""
	}

	encodedData := base64.URLEncoding.EncodeToString(jsonData)

	return encodedData
}
