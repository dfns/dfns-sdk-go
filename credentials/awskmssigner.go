package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types" // added import for constants

	"github.com/dfns/dfns-sdk-go/internal/credentials"
)

// enforce that AWSKMSSigner implements credentials.ICredentialSigner
var _ credentials.ICredentialSigner = (*AWSKMSSigner)(nil)

// AWSKMSClient defines the subset of the AWS KMS client's functionality used here.
type AWSKMSClient interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

// AWSKMSSignerConfig holds the configuration for the AWS KMS signer.
type AWSKMSSignerConfig struct {
	KeyID            string // The AWS KMS key identifier
	Region           string // The AWS region
	SigningAlgorithm types.SigningAlgorithmSpec
}

// AWSKMSSigner implements credentials.ICredentialSigner using AWS KMS.
type AWSKMSSigner struct {
	config    *AWSKMSSignerConfig
	kmsClient AWSKMSClient
}

func WithAWSKMSClient(client AWSKMSClient) func(*AWSKMSSigner) {
	return func(sgn *AWSKMSSigner) {
		sgn.kmsClient = client
	}
}

// NewAWSKMSSigner creates a new Signer instance using a real KMS client.
func NewAWSKMSSigner(
	ctx context.Context,
	cfgSigner *AWSKMSSignerConfig,
	options ...func(*AWSKMSSigner),
) (*AWSKMSSigner, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	newSgn := &AWSKMSSigner{
		config: cfgSigner,
	}

	for _, opt := range options {
		opt(newSgn)
	}

	if newSgn.kmsClient == nil {
		client := kms.NewFromConfig(cfg)
		newSgn.kmsClient = client
	}

	var (
		sas      types.SigningAlgorithmSpec
		sasFound bool
	)

	for _, sasv := range sas.Values() {
		if sasv == newSgn.config.SigningAlgorithm {
			sasFound = true

			break
		}
	}

	if !sasFound {
		return nil, fmt.Errorf("invalid signing algorithm: %v", newSgn.config.SigningAlgorithm)
	}

	return newSgn, nil
}

// Sign implements the credentials.ICredentialSigner interface.
func (akss *AWSKMSSigner) Sign(
	ctx context.Context,
	userActionChallenge *credentials.UserActionChallenge,
) (*credentials.KeyAssertion, error) {
	if userActionChallenge.AllowCredentials != nil {
		allowed := false

		for _, cred := range userActionChallenge.AllowCredentials.Key {
			if cred.ID == akss.config.KeyID {
				allowed = true

				break
			}
		}

		if !allowed {
			return nil, &credentials.NotAllowedCredentialsError{
				CredID:       akss.config.KeyID,
				AllowedCreds: userActionChallenge.AllowCredentials.Key,
			}
		}
	}

	clientData := struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}{
		Type:      "key.get",
		Challenge: userActionChallenge.Challenge,
	}

	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client data: %w", err)
	}

	input := &kms.SignInput{
		KeyId:            aws.String(akss.config.KeyID),
		Message:          clientDataJSON,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: akss.config.SigningAlgorithm,
	}

	output, err := akss.kmsClient.Sign(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data with AWS KMS: %w", err)
	}

	signatureBytes := output.Signature

	keyAssertion := &credentials.KeyAssertion{
		Kind: credentials.KeyCredential,
		CredentialAssertion: credentials.CredentialAssertion{
			CredID:     akss.config.KeyID,
			Signature:  base64.RawURLEncoding.EncodeToString(signatureBytes),
			ClientData: base64.RawURLEncoding.EncodeToString(clientDataJSON),
			Algorithm:  string(akss.config.SigningAlgorithm),
		},
	}

	return keyAssertion, nil
}
