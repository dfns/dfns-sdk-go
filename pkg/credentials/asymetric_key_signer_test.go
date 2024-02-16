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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAsymmetricKeySigner_SignAndVerify_RSA_PKS1(t *testing.T) {
	// Generate a new RSA private key
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// PKS1
	rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey)})

	conf := &AsymmetricKeySignerConfig{
		PrivateKey: string(rsaPrivateKeyPEM),
		CredId:     "mockCredId",
		AppOrigin:  "mockAppOrigin",
	}

	signer := NewAsymmetricKeySigner(conf)

	challenge := "mockChallenge"

	// Sign the challenge
	keyAssertion, err := signer.Sign(challenge, nil)
	assert.NoError(t, err)
	assert.NotNil(t, keyAssertion)

	// Verify the signature
	clientDataBytes := []byte(`{"type":"key.get","challenge":"mockChallenge","origin":"mockAppOrigin","crossOrigin":false}`)
	h := crypto.SHA256.New()
	h.Write(clientDataBytes)

	signature, err := base64.RawURLEncoding.DecodeString(keyAssertion.CredentialAssertion.Signature)
	assert.NoError(t, err)

	err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, h.Sum(nil), signature)
	assert.NoError(t, err)
}

func TestAsymmetricKeySigner_SignAndVerify_RSA_PKS8(t *testing.T) {
	// Generate a new RSA private key
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// PKS8
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	assert.NoError(t, err)

	rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})

	conf := &AsymmetricKeySignerConfig{
		PrivateKey: string(rsaPrivateKeyPEM),
		CredId:     "mockCredId",
		AppOrigin:  "mockAppOrigin",
	}

	signer := NewAsymmetricKeySigner(conf)

	challenge := "mockChallenge"

	// Sign the challenge
	keyAssertion, err := signer.Sign(challenge, nil)
	assert.NoError(t, err)
	assert.NotNil(t, keyAssertion)

	// Verify the signature
	clientDataBytes := []byte(`{"type":"key.get","challenge":"mockChallenge","origin":"mockAppOrigin","crossOrigin":false}`)
	h := crypto.SHA256.New()
	h.Write(clientDataBytes)

	signature, err := base64.RawURLEncoding.DecodeString(keyAssertion.CredentialAssertion.Signature)
	assert.NoError(t, err)

	err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, h.Sum(nil), signature)
	assert.NoError(t, err)
}

func TestAsymmetricKeySigner_SignAndVerify_ECDSA(t *testing.T) {
	// Generate a new ECDSA private key
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	ecdsaPrivateKeyDER, err := x509.MarshalECPrivateKey(ecdsaPrivateKey)
	assert.NoError(t, err)
	ecdsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaPrivateKeyDER})

	conf := &AsymmetricKeySignerConfig{
		PrivateKey: string(ecdsaPrivateKeyPEM),
		CredId:     "mockCredId",
		AppOrigin:  "mockAppOrigin",
	}

	signer := NewAsymmetricKeySigner(conf)

	challenge := "mockChallenge"

	// Sign the challenge
	keyAssertion, err := signer.Sign(challenge, nil)
	assert.NoError(t, err)
	assert.NotNil(t, keyAssertion)

	// Verify the signature
	clientDataBytes := []byte(`{"type":"key.get","challenge":"mockChallenge","origin":"mockAppOrigin","crossOrigin":false}`)
	h := crypto.SHA256.New()
	h.Write(clientDataBytes)

	signature, err := base64.RawURLEncoding.DecodeString(keyAssertion.CredentialAssertion.Signature)
	assert.NoError(t, err)

	valid := ecdsa.VerifyASN1(&ecdsaPrivateKey.PublicKey, h.Sum(nil), signature)
	assert.True(t, valid)
}

func TestAsymmetricKeySigner_SignAndVerify_Ed25519(t *testing.T) {
	// Generate a new Ed25519 private key
	ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	eddsaPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(ed25519PrivateKey)
	assert.NoError(t, err)

	eddsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: eddsaPrivateKeyDER})

	conf := &AsymmetricKeySignerConfig{
		PrivateKey: string(eddsaPrivateKeyPEM),
		CredId:     "mockCredId",
		AppOrigin:  "mockAppOrigin",
	}

	signer := NewAsymmetricKeySigner(conf)

	challenge := "mockChallenge"

	// Sign the challenge
	keyAssertion, err := signer.Sign(challenge, nil)
	assert.NoError(t, err)
	assert.NotNil(t, keyAssertion)

	// Verify the signature
	clientDataBytes := []byte(`{"type":"key.get","challenge":"mockChallenge","origin":"mockAppOrigin","crossOrigin":false}`)

	signature, err := base64.RawURLEncoding.DecodeString(keyAssertion.CredentialAssertion.Signature)
	assert.NoError(t, err)

	valid := ed25519.Verify(ed25519PublicKey, clientDataBytes, signature)
	assert.True(t, valid)
}
