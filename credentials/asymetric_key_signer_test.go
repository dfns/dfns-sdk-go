package credentials

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/dfns/dfns-sdk-go/internal/credentials"
)

func TestAsymmetricKeySigner_SignAndVerify_RSA_PKS1(t *testing.T) {
	t.Parallel()

	credID := "mockCredId"
	challenge := "mockChallenge"

	// Generate a new RSA private key
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// PKS1
	rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey)})

	conf := &AsymmetricKeySignerConfig{
		PrivateKey: string(rsaPrivateKeyPEM),
		CredID:     credID,
	}

	signer := NewAsymmetricKeySigner(conf)

	// Sign the challenge
	keyAssertion, err := signer.Sign(&credentials.UserActionChallenge{
		Challenge: challenge,
		AllowCredentials: &credentials.AllowCredentials{
			Key: []credentials.AllowCredential{
				{
					ID: credID,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the signature
	clientDataBytes := []byte(`{"type":"key.get","challenge":"mockChallenge"}`)
	h := crypto.SHA256.New()
	h.Write(clientDataBytes)

	signature, err := base64.RawURLEncoding.DecodeString(keyAssertion.CredentialAssertion.Signature)
	if err != nil {
		t.Fatal(err)
	}

	err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, h.Sum(nil), signature)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAsymmetricKeySigner_SignAndVerify_RSA_PKS8(t *testing.T) {
	t.Parallel()

	credID := "mockCredId"
	challenge := "mockChallenge"

	// Generate a new RSA private key
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// PKS8
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})

	conf := &AsymmetricKeySignerConfig{
		PrivateKey: string(rsaPrivateKeyPEM),
		CredID:     credID,
	}

	signer := NewAsymmetricKeySigner(conf)

	// Sign the challenge
	keyAssertion, err := signer.Sign(&credentials.UserActionChallenge{
		Challenge: challenge,
		AllowCredentials: &credentials.AllowCredentials{
			Key: []credentials.AllowCredential{
				{
					ID: credID,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the signature
	clientDataBytes := []byte(`{"type":"key.get","challenge":"mockChallenge"}`)
	h := crypto.SHA256.New()
	h.Write(clientDataBytes)

	signature, err := base64.RawURLEncoding.DecodeString(keyAssertion.CredentialAssertion.Signature)
	if err != nil {
		t.Fatal(err)
	}

	err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, h.Sum(nil), signature)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAsymmetricKeySigner_SignAndVerify_ECDSA(t *testing.T) {
	t.Parallel()

	credID := "mockCredId"
	challenge := "mockChallenge"

	// Generate a new ECDSA private key
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaPrivateKeyDER, err := x509.MarshalECPrivateKey(ecdsaPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaPrivateKeyDER})

	conf := &AsymmetricKeySignerConfig{
		PrivateKey: string(ecdsaPrivateKeyPEM),
		CredID:     credID,
	}

	signer := NewAsymmetricKeySigner(conf)

	// Sign the challenge
	keyAssertion, err := signer.Sign(&credentials.UserActionChallenge{
		Challenge: challenge,
		AllowCredentials: &credentials.AllowCredentials{
			Key: []credentials.AllowCredential{
				{
					ID: credID,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the signature
	clientDataBytes := []byte(`{"type":"key.get","challenge":"mockChallenge"}`)
	h := crypto.SHA256.New()
	h.Write(clientDataBytes)

	signature, err := base64.RawURLEncoding.DecodeString(keyAssertion.CredentialAssertion.Signature)
	if err != nil {
		t.Fatal(err)
	}

	valid := ecdsa.VerifyASN1(&ecdsaPrivateKey.PublicKey, h.Sum(nil), signature)
	if !valid {
		t.Fatal("ECDSA signature verification failed")
	}
}

func TestAsymmetricKeySigner_SignAndVerify_Ed25519(t *testing.T) {
	t.Parallel()

	credID := "mockCredId"
	challenge := "mockChallenge"

	// Generate a new Ed25519 private key
	ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	eddsaPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(ed25519PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	eddsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: eddsaPrivateKeyDER})

	conf := &AsymmetricKeySignerConfig{
		PrivateKey: string(eddsaPrivateKeyPEM),
		CredID:     credID,
	}

	signer := NewAsymmetricKeySigner(conf)

	// Sign the challenge
	keyAssertion, err := signer.Sign(&credentials.UserActionChallenge{
		Challenge: challenge,
		AllowCredentials: &credentials.AllowCredentials{
			Key: []credentials.AllowCredential{
				{
					ID: credID,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the signature
	clientDataBytes := []byte(`{"type":"key.get","challenge":"mockChallenge"}`)

	signature, err := base64.RawURLEncoding.DecodeString(keyAssertion.CredentialAssertion.Signature)
	if err != nil {
		t.Fatal(err)
	}

	valid := ed25519.Verify(ed25519PublicKey, clientDataBytes, signature)
	if !valid {
		t.Fatal("Ed25519 signature verification failed")
	}
}

func TestAsymmetricKeySigner_Sign_InvalidPEMFormat(t *testing.T) {
	t.Parallel()

	challenge := "mockChallenge"
	credID := "mockCredId"

	conf := &AsymmetricKeySignerConfig{
		PrivateKey: "invalid PEM format",
		CredID:     credID,
	}

	signer := NewAsymmetricKeySigner(conf)

	_, err := signer.Sign(&credentials.UserActionChallenge{
		Challenge: challenge,
		AllowCredentials: &credentials.AllowCredentials{
			Key: []credentials.AllowCredential{
				{
					ID: credID,
				},
			},
		},
	})
	if errors.Unwrap(err).Error() != errFailedToDecodePEMBlock.Error() {
		t.Fatalf("Expected an error due to invalid PEM format, but got %s", err)
	}
}

func TestAsymmetricKeySigner_Sign_NotAllowedCredential(t *testing.T) {
	t.Parallel()

	challenge := "mockChallenge"
	credID := "mockCredId"

	conf := &AsymmetricKeySignerConfig{
		PrivateKey: "invalid PEM format",
		CredID:     credID,
	}

	signer := NewAsymmetricKeySigner(conf)

	_, err := signer.Sign(&credentials.UserActionChallenge{
		Challenge: challenge,
		AllowCredentials: &credentials.AllowCredentials{
			Key: []credentials.AllowCredential{
				{
					ID: "otherCredID",
				},
			},
		},
	})
	if errors.Unwrap(err).Error() != errNotAllowedCredentials.Error() {
		t.Fatalf("Expected an error due to invalid credID, but got %s", err)
	}
}
