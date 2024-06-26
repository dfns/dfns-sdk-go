package credentials

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/dfns/dfns-sdk-go/internal/credentials"
)

var (
	errFailedToDecodePEMBlock    = errors.New("failed to decode PEM block")
	errUnsupportedPrivateKeyType = errors.New("unsupported private key type")
	errNotAllowedCredentials     = errors.New("not allowed credentials")
)

type AsymmetricKeySignerConfig struct {
	// PrivateKey holds the PEM-encoded private key used for signing.
	PrivateKey string
	// CredID is the identifier of the credential associated with the private key.
	CredID string
	// Algorithm specifies the hashing algorithm to use for signing. Defaults to SHA256 if not set.
	Algorithm *crypto.Hash
}

type AsymmetricKeySigner struct {
	*AsymmetricKeySignerConfig
}

// NewAsymmetricKeySigner creates a new instance of AsymmetricKeySigner with the provided configuration.
func NewAsymmetricKeySigner(config *AsymmetricKeySignerConfig) *AsymmetricKeySigner {
	return &AsymmetricKeySigner{
		AsymmetricKeySignerConfig: config,
	}
}

// Sign signs the given challenge using the private key and the hashing
// algorithm specified in the Algorithm field. If the Algorithm field is
// not set or invalid, it defaults to SHA256.
func (signer *AsymmetricKeySigner) Sign(
	userActionChallenge *credentials.UserActionChallenge,
) (*credentials.KeyAssertion, error) {
	allowedIDs := []string{}
	hasCredID := false

	for _, cred := range userActionChallenge.AllowCredentials.Key {
		if cred.ID == signer.CredID {
			hasCredID = true
		}

		allowedIDs = append(allowedIDs, cred.ID)
	}

	if !hasCredID {
		return nil, fmt.Errorf("%w: %s does not match allowed credentials: %v",
			errNotAllowedCredentials, signer.CredID, allowedIDs)
	}

	// Determine the hashing algorithm
	hash := signer.Algorithm
	if hash == nil {
		c := crypto.SHA256
		hash = &c
	}

	// Parse PEM encoded private key
	privateKey, err := parsePEMPrivateKey(signer.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("can't parse PEM format: %w", err)
	}

	clientData := struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}{
		Type:      "key.get",
		Challenge: userActionChallenge.Challenge,
	}

	// Marshal the clientData object to JSON
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling client data: %w", err)
	}

	signature, err := signData(privateKey, hash, clientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("can't sign data: %w", err)
	}

	// Construct the key assertion
	keyAssertion := &credentials.KeyAssertion{
		Kind: credentials.KeyCredential,
		CredentialAssertion: credentials.CredentialAssertion{
			CredID:     signer.CredID,
			Signature:  base64.RawURLEncoding.EncodeToString(signature),
			ClientData: base64.RawURLEncoding.EncodeToString(clientDataJSON),
			Algorithm:  hash.String(),
		},
	}

	return keyAssertion, nil
}

func parsePEMPrivateKey(privateKey string) (interface{}, error) {
	// Parse PEM encoded private key
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errFailedToDecodePEMBlock
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}

		return key, nil

	case "PRIVATE KEY":
		// ed + rsa_pk8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}

		return key, nil

	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}

		return key, nil

	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedPrivateKeyType, block.Type)
	}
}

func signData(privateKey interface{}, hash *crypto.Hash, data []byte) ([]byte, error) {
	switch privateKey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		h := hash.New()
		h.Write(data)

		signature, err := ecdsa.SignASN1(rand.Reader, privateKey, h.Sum(nil))
		if err != nil {
			return nil, fmt.Errorf("failed to sign with ECDSA private key: %w", err)
		}

		return signature, nil
	case *rsa.PrivateKey:
		h := hash.New()
		h.Write(data)

		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, *hash, h.Sum(nil))
		if err != nil {
			return nil, fmt.Errorf("failed to sign with RSA private key: %w", err)
		}

		return signature, nil
	case ed25519.PrivateKey:
		return ed25519.Sign(privateKey, data), nil
	default:
		return nil, fmt.Errorf("%w: %T", errUnsupportedPrivateKeyType, privateKey)
	}
}
