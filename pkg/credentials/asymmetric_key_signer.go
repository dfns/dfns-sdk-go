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
)

type AsymmetricKeySignerConfig struct {
	PrivateKey  string
	CredId      string
	AppOrigin   string
	CrossOrigin *bool
	Algorithm   *crypto.Hash
}

type AsymmetricKeySigner struct {
	*AsymmetricKeySignerConfig
}

func NewAsymmetricKeySigner(config *AsymmetricKeySignerConfig) *AsymmetricKeySigner {
	return &AsymmetricKeySigner{
		AsymmetricKeySignerConfig: config,
	}
}

// Sign signs the given challenge using the private key and the hashing algorithm specified in the Algorithm field.
// If the Algorithm field is not set or invalid, it defaults to SHA256.
func (signer *AsymmetricKeySigner) Sign(challenge string, allowCredentials *AllowCredentials) (*KeyAssertion, error) {
	// Determine the hashing algorithm
	hash := signer.Algorithm
	if hash == nil {
		c := crypto.SHA256
		hash = &c
	}

	// Parse PEM encoded private key
	block, _ := pem.Decode([]byte(signer.PrivateKey))
	if block == nil {
		return nil, errors.New("invalid PrivateKey PEM format")
	}

	var privateKey interface{}
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		// ed + rsa_pk8
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
	if err != nil {
		return nil, err
	}

	var crossOrigin bool
	if signer.CrossOrigin != nil {
		crossOrigin = *signer.CrossOrigin
	}

	clientData := struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{
		Type:        "key.get",
		Challenge:   challenge,
		Origin:      signer.AppOrigin,
		CrossOrigin: crossOrigin,
	}

	// Marshal the clientData object to JSON
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling client data: %v", err)
	}

	// Sign the challenge (or the hash)
	var signature []byte
	switch privateKey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		h := hash.New()
		h.Write(clientDataJSON)

		signature, err = ecdsa.SignASN1(rand.Reader, privateKey, h.Sum(nil))
		if err != nil {
			return nil, err
		}

	case *rsa.PrivateKey:
		h := hash.New()
		h.Write(clientDataJSON)
		signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, *hash, h.Sum(nil))
		if err != nil {
			return nil, err
		}
	case ed25519.PrivateKey:
		signature = ed25519.Sign(privateKey, clientDataJSON)
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	// Construct the key assertion
	keyAssertion := &KeyAssertion{
		Kind: KeyCredential,
		CredentialAssertion: CredentialAssertion{
			CredId:     signer.CredId,
			Signature:  base64.RawURLEncoding.EncodeToString(signature),
			ClientData: base64.RawURLEncoding.EncodeToString(clientDataJSON),
			Algorithm:  hash.String(),
		},
	}

	return keyAssertion, nil
}
