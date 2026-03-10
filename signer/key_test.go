package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func generateEd25519PEM(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	return pub, marshalPKCS8PEM(t, priv)
}

func generateECDSAPEM(t *testing.T) (*ecdsa.PublicKey, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	return &priv.PublicKey, marshalPKCS8PEM(t, priv)
}

func generateRSAPEM(t *testing.T) (*rsa.PublicKey, string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	return &priv.PublicKey, marshalPKCS8PEM(t, priv)
}

func marshalPKCS8PEM(t *testing.T, key interface{}) string {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8 key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestNewKeySigner_EmptyCredentialID(t *testing.T) {
	t.Parallel()

	_, err := NewKeySigner("", "some-pem")
	if err == nil || !strings.Contains(err.Error(), "credentialID is required") {
		t.Fatalf("expected credentialID error, got: %v", err)
	}
}

func TestNewKeySigner_EmptyPEM(t *testing.T) {
	t.Parallel()

	_, err := NewKeySigner("cred-1", "")
	if err == nil || !strings.Contains(err.Error(), "privateKeyPEM is required") {
		t.Fatalf("expected privateKeyPEM error, got: %v", err)
	}
}

func TestNewKeySigner_InvalidPEM(t *testing.T) {
	t.Parallel()

	_, err := NewKeySigner("cred-1", "not-a-pem-block")
	if err == nil || !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Fatalf("expected PEM decode error, got: %v", err)
	}
}

func TestNewKeySigner_BadPEMContent(t *testing.T) {
	t.Parallel()

	badPEM := "-----BEGIN PRIVATE KEY-----\nYmFkLWtleS1kYXRh\n-----END PRIVATE KEY-----"

	_, err := NewKeySigner("cred-1", badPEM)
	if err == nil || !strings.Contains(err.Error(), "unable to parse private key") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestNewKeySigner_Ed25519(t *testing.T) {
	t.Parallel()

	_, pemKey := generateEd25519PEM(t)

	s, err := NewKeySigner("cred-ed25519", pemKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.CredentialID != "cred-ed25519" {
		t.Fatalf("expected credentialID=cred-ed25519, got %s", s.CredentialID)
	}
}

func TestNewKeySigner_ECDSA(t *testing.T) {
	t.Parallel()

	_, pemKey := generateECDSAPEM(t)

	_, err := NewKeySigner("cred-ecdsa", pemKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewKeySigner_ECDSA_ECFormat(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}

	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	_, err = NewKeySigner("cred-ec", pemKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewKeySigner_RSA(t *testing.T) {
	t.Parallel()

	_, pemKey := generateRSAPEM(t)

	_, err := NewKeySigner("cred-rsa", pemKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewKeySigner_RSA_PKCS1Format(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	der := x509.MarshalPKCS1PrivateKey(priv)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))

	_, err = NewKeySigner("cred-rsa-pkcs1", pemKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSign_NilChallenge(t *testing.T) {
	t.Parallel()

	_, pemKey := generateEd25519PEM(t)

	s, err := NewKeySigner("cred-1", pemKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = s.Sign(nil)
	if err == nil || !strings.Contains(err.Error(), "challenge is required") {
		t.Fatalf("expected challenge error, got: %v", err)
	}
}

func TestSign_Ed25519_VerifySignature(t *testing.T) {
	t.Parallel()

	pub, pemKey := generateEd25519PEM(t)

	s, err := NewKeySigner("cred-ed", pemKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	challenge := &UserActionChallenge{
		ChallengeIdentifier: "challenge-id-123",
		Challenge:           "dGVzdC1jaGFsbGVuZ2U",
	}

	assertion, err := s.Sign(challenge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertAssertionStructure(t, assertion, "cred-ed", challenge.Challenge)

	clientData, _ := base64.RawURLEncoding.DecodeString(assertion.CredentialAssertion.ClientData)
	sig, _ := base64.RawURLEncoding.DecodeString(assertion.CredentialAssertion.Signature)

	if !ed25519.Verify(pub, clientData, sig) {
		t.Fatal("ed25519 signature verification failed")
	}
}

func TestSign_ECDSA_VerifySignature(t *testing.T) {
	t.Parallel()

	pub, pemKey := generateECDSAPEM(t)

	s, err := NewKeySigner("cred-ec", pemKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	challenge := &UserActionChallenge{
		ChallengeIdentifier: "challenge-id-456",
		Challenge:           "ZWNkc2EtY2hhbGxlbmdl",
	}

	assertion, err := s.Sign(challenge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertAssertionStructure(t, assertion, "cred-ec", challenge.Challenge)

	clientData, _ := base64.RawURLEncoding.DecodeString(assertion.CredentialAssertion.ClientData)
	sig, _ := base64.RawURLEncoding.DecodeString(assertion.CredentialAssertion.Signature)

	hash := sha256.Sum256(clientData)

	if !ecdsa.VerifyASN1(pub, hash[:], sig) {
		t.Fatal("ecdsa signature verification failed")
	}
}

func TestSign_RSA_VerifySignature(t *testing.T) {
	t.Parallel()

	pub, pemKey := generateRSAPEM(t)

	s, err := NewKeySigner("cred-rsa", pemKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	challenge := &UserActionChallenge{
		ChallengeIdentifier: "challenge-id-789",
		Challenge:           "cnNhLWNoYWxsZW5nZQ",
	}

	assertion, err := s.Sign(challenge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertAssertionStructure(t, assertion, "cred-rsa", challenge.Challenge)

	clientData, _ := base64.RawURLEncoding.DecodeString(assertion.CredentialAssertion.ClientData)
	sig, _ := base64.RawURLEncoding.DecodeString(assertion.CredentialAssertion.Signature)

	hash := sha256.Sum256(clientData)

	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig); err != nil {
		t.Fatalf("rsa signature verification failed: %v", err)
	}
}

func TestSign_ClientDataFormat(t *testing.T) {
	t.Parallel()

	_, pemKey := generateEd25519PEM(t)

	s, err := NewKeySigner("cred-1", pemKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	challenge := &UserActionChallenge{
		ChallengeIdentifier: "cid",
		Challenge:           "test-challenge-value",
	}

	assertion, err := s.Sign(challenge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	clientDataBytes, err := base64.RawURLEncoding.DecodeString(assertion.CredentialAssertion.ClientData)
	if err != nil {
		t.Fatalf("failed to decode clientData: %v", err)
	}

	var clientData map[string]interface{}
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		t.Fatalf("failed to unmarshal clientData: %v", err)
	}

	if clientData["type"] != "key.get" {
		t.Errorf("expected type=key.get, got %v", clientData["type"])
	}

	if clientData["challenge"] != "test-challenge-value" {
		t.Errorf("expected challenge=test-challenge-value, got %v", clientData["challenge"])
	}

	if clientData["crossOrigin"] != false {
		t.Errorf("expected crossOrigin=false, got %v", clientData["crossOrigin"])
	}
}

func TestSign_UnsupportedKeyType(t *testing.T) {
	t.Parallel()

	s := &KeySigner{
		CredentialID: "cred-unsupported",
		privateKey:   "not-a-real-key",
	}

	challenge := &UserActionChallenge{
		ChallengeIdentifier: "challenge-unsupported",
		Challenge:           "dGVzdA",
	}

	_, err := s.Sign(challenge)
	if err == nil || !strings.Contains(err.Error(), "unsupported key type") {
		t.Fatalf("expected unsupported key type error, got: %v", err)
	}
}

func assertAssertionStructure(t *testing.T, assertion *CredentialAssertion, expectedCredID, expectedChallenge string) {
	t.Helper()

	if assertion.Kind != "Key" {
		t.Errorf("expected kind=Key, got %s", assertion.Kind)
	}

	if assertion.CredentialAssertion.CredID != expectedCredID {
		t.Errorf("expected credID=%s, got %s", expectedCredID, assertion.CredentialAssertion.CredID)
	}

	if assertion.CredentialAssertion.ClientData == "" {
		t.Error("expected non-empty clientData")
	}

	if assertion.CredentialAssertion.Signature == "" {
		t.Error("expected non-empty signature")
	}

	if strings.ContainsAny(assertion.CredentialAssertion.ClientData, "+/=") {
		t.Error("clientData contains non-URL-safe base64 characters")
	}

	if strings.ContainsAny(assertion.CredentialAssertion.Signature, "+/=") {
		t.Error("signature contains non-URL-safe base64 characters")
	}

	clientDataBytes, err := base64.RawURLEncoding.DecodeString(assertion.CredentialAssertion.ClientData)
	if err != nil {
		t.Fatalf("failed to decode clientData: %v", err)
	}

	var clientData map[string]interface{}
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		t.Fatalf("failed to unmarshal clientData: %v", err)
	}

	if clientData["challenge"] != expectedChallenge {
		t.Errorf("expected challenge=%s in clientData, got %v", expectedChallenge, clientData["challenge"])
	}
}
