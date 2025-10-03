package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/dfns/dfns-sdk-go/internal/credentials"
)

// mockKMSClient is a mock implementation of the KMSClient interface.
type mockKMSClient struct{}

// Sign returns a fixed signature value for testing.
func (m *mockKMSClient) Sign(
	_ context.Context,
	_ *kms.SignInput,
	_ ...func(*kms.Options),
) (*kms.SignOutput, error) {
	// Return the simulated signature.
	return &kms.SignOutput{Signature: []byte("aws-kms-signature")}, nil
}

// errorKMSClient is a mock implementation that returns an error.
type errorKMSClient struct{}

func (e *errorKMSClient) Sign(_ context.Context, _ *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	return nil, errors.New("simulated kms error")
}

func TestAWSKMSSigner_Sign(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	config := &AWSKMSSignerConfig{
		KeyID:            "test-key-id",
		Region:           "us-west-2",
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	}
	// Inject the mock client.
	signer, errS := NewAWSKMSSigner(ctx, config, WithAWSKMSClient(&mockKMSClient{}))
	if errS != nil {
		t.Fatalf("Expected no error, got: %v", errS)
	}

	challengeText := "test-challenge"
	userActionChallenge := &credentials.UserActionChallenge{
		Challenge: challengeText,
		// ...existing code for allow credentials if needed...
	}

	keyAssertion, err := signer.Sign(context.Background(), userActionChallenge)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Check that the returned fields match our simulated values.
	expectedSignature := base64.RawURLEncoding.EncodeToString([]byte("aws-kms-signature"))
	if keyAssertion.CredentialAssertion.Signature != expectedSignature {
		t.Errorf("Expected signature %s, got: %s", expectedSignature, keyAssertion.CredentialAssertion.Signature)
	}

	// Validate client data.
	expectedClientData := struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}{
		Type:      "key.get",
		Challenge: challengeText,
	}

	expectedJSON, err := json.Marshal(expectedClientData)
	if err != nil {
		t.Fatalf("Failed to marshal expected client data: %v", err)
	}

	expectedClientDataB64 := base64.RawURLEncoding.EncodeToString(expectedJSON)
	if keyAssertion.CredentialAssertion.ClientData != expectedClientDataB64 {
		t.Errorf("Expected clientData %s, got: %s", expectedClientDataB64, keyAssertion.CredentialAssertion.ClientData)
	}

	if keyAssertion.CredentialAssertion.Algorithm != string(types.SigningAlgorithmSpecRsassaPkcs1V15Sha256) {
		t.Errorf("Unexpected algorithm: %s", keyAssertion.CredentialAssertion.Algorithm)
	}

	if keyAssertion.CredentialAssertion.CredID != config.KeyID {
		t.Errorf("Expected CredID %s, got: %s", config.KeyID, keyAssertion.CredentialAssertion.CredID)
	}
}

func TestAWSKMSSigner_Sign_Error(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	config := &AWSKMSSignerConfig{
		KeyID:            "error-key-id",
		Region:           "us-west-2",
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	}
	// Inject the error mock client.
	signer, err := NewAWSKMSSigner(ctx, config, WithAWSKMSClient(&errorKMSClient{}))
	if err != nil {
		t.Fatalf("Expected no error when creating signer, got: %v", err)
	}

	userActionChallenge := &credentials.UserActionChallenge{
		Challenge: "error-challenge",
		// ...existing code...
	}

	_, err = signer.Sign(context.Background(), userActionChallenge)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "simulated kms error") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestAWSKMSSigner_Sign_NotAllowedCredentials(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	config := &AWSKMSSignerConfig{
		KeyID:            "test-key-id",
		Region:           "us-west-2",
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	}
	// Use the mock client to bypass the actual KMS call.
	signer, err := NewAWSKMSSigner(ctx, config, WithAWSKMSClient(&mockKMSClient{}))
	if err != nil {
		t.Fatalf("Expected no error when creating signer, got: %v", err)
	}

	// Create a challenge with an allowed credential that does not include our KeyID.
	userActionChallenge := &credentials.UserActionChallenge{
		Challenge: "test-challenge",
		AllowCredentials: &credentials.AllowCredentials{
			Key: []credentials.AllowCredential{
				{ID: "another-key", Type: "key"},
			},
		},
	}

	_, err = signer.Sign(context.Background(), userActionChallenge)
	if err == nil {
		t.Fatal("Expected error due to not allowed credentials, got none")
	}

	// Verify that the error is of type NotAllowedCredentialsError.
	if _, ok := err.(*credentials.NotAllowedCredentialsError); !ok {
		t.Fatalf("Expected NotAllowedCredentialsError, got error: %v", err)
	}
}

// Test that the NewAWSKMSSigner function returns an error when the signing algorithm is invalid.
func TestNewAWSKMSSigner_InvalidSigningAlgorithm(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	config := &AWSKMSSignerConfig{
		KeyID:            "test-key-id",
		Region:           "us-west-2",
		SigningAlgorithm: "invalid-algorithm",
	}

	_, err := NewAWSKMSSigner(ctx, config)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "invalid signing algorithm") {
		t.Errorf("Unexpected error: %v", err)
	}
}
