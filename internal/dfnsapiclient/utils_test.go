package dfnsapiclient

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

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

//nolint:paralleltest // AssertAuthTokenIsSameOrg is modified in other functions
func TestAssertAuthTokenIsSameOrg_Unit(t *testing.T) {
	type args struct {
		authToken string
		orgID     string
	}

	makeJWT := func(orgID any, includeClaim bool) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		payloadMap := map[string]interface{}{}

		if includeClaim {
			payloadMap[JwtCustomDataClaim] = map[string]interface{}{"orgId": orgID}
		}

		payloadBytes, err := json.Marshal(payloadMap)
		if err != nil {
			t.Fatal(err)
		}

		payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

		return header + "." + payload + "."
	}

	tests := []struct {
		name        string
		args        args
		wantErr     bool
		errContains string
	}{
		{
			name: "valid orgId match",
			args: args{
				authToken: makeJWT("org-abc", true),
				orgID:     "org-abc",
			},
			wantErr: false,
		},
		{
			name: "orgId mismatch",
			args: args{
				authToken: makeJWT("org-def", true),
				orgID:     "org-abc",
			},
			wantErr:     true,
			errContains: "provided auth token is not scoped to org ID",
		},
		{
			name: "missing orgId in claim",
			args: args{
				authToken: makeJWT(nil, true),
				orgID:     "org-abc",
			},
			wantErr:     true,
			errContains: "orgId claim not found",
		},
		{
			name: "missing custom data claim",
			args: args{
				authToken: makeJWT(nil, false),
				orgID:     "org-abc",
			},
			wantErr:     true,
			errContains: "orgId claim not found",
		},
		{
			name: "invalid JWT format",
			args: args{
				authToken: "invalid.token",
				orgID:     "org-abc",
			},
			wantErr:     true,
			errContains: "invalid JWT format",
		},
		{
			name: "invalid payload base64",
			args: args{
				authToken: "aW52YWxpZA==.!!!.c2ln",
				orgID:     "org-abc",
			},
			wantErr:     true,
			errContains: "failed to decode JWT payload",
		},
		{
			name: "invalid payload json",
			args: args{
				authToken: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
					base64.RawURLEncoding.EncodeToString([]byte("{not-json")) + ".",
				orgID: "org-abc",
			},
			wantErr:     true,
			errContains: "failed to unmarshal JWT payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AssertAuthTokenIsSameOrg(tt.args.authToken, tt.args.orgID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}

				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}
		})
	}
}
