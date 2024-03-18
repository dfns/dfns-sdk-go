package dfns_api_client

import (
	"errors"
	"net/http"

	"github.com/dfns/dfns-sdk-go/pkg/credentials"
)

// DfnsApiConfig defines the configuration options for the DFNS API.
type DfnsApiConfig struct {
	AppId     string  // The application ID for authentication
	AuthToken *string // The authentication token
	BaseUrl   string  // The base URL of the DFNS API
}

type DfnsApiOptions struct {
	*DfnsApiConfig                               // Configuration for DFNS API
	Signer         credentials.ICredentialSigner // The credential signer for signing user actions
}

// NewDfnsApiOptions creates a new DfnsApiOptions instance with the provided parameters.
func NewDfnsApiOptions(config *DfnsApiConfig, signer credentials.ICredentialSigner) (*DfnsApiOptions, error) {
	if config.AppId == "" {
		return nil, errors.New("AppId cannot be empty")
	}
	if config.BaseUrl == "" {
		return nil, errors.New("BaseUrl cannot be empty")
	}

	return &DfnsApiOptions{
		DfnsApiConfig: config,
		Signer:        signer,
	}, nil
}

func CreateDfnsApiClient(options *DfnsApiOptions) *http.Client {
	return &http.Client{
		Transport: &authTransport{
			DfnsApiOptions: options,
		},
	}
}
