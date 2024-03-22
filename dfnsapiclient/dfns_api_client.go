package dfnsapiclient

import (
	"errors"
	"net/http"

	"github.com/dfns/dfns-sdk-go/internal/credentials"
	dfnsapi "github.com/dfns/dfns-sdk-go/internal/dfnsapiclient"
)

var (
	ErrBaseURLEmpty = errors.New("BaseUrl cannot be empty")
	ErrAppIDEmpty   = errors.New("AppID cannot be empty")
)

// DfnsAPIConfig defines the configuration options for the DFNS API.
type DfnsAPIConfig struct {
	AppID     string  // The application ID for authentication
	AuthToken *string // The authentication token
	BaseURL   string  // The base URL of the DFNS API
}

type DfnsAPIOptions struct {
	*DfnsAPIConfig                               // Configuration for DFNS API
	Signer         credentials.ICredentialSigner // The credential signer for signing user actions
}

// NewDfnsAPIOptions creates a new DfnsApiOptions instance with the provided parameters.
func NewDfnsAPIOptions(config *DfnsAPIConfig, signer credentials.ICredentialSigner) (*DfnsAPIOptions, error) {
	if config.AppID == "" {
		return nil, ErrAppIDEmpty
	}

	if config.BaseURL == "" {
		return nil, ErrBaseURLEmpty
	}

	return &DfnsAPIOptions{
		DfnsAPIConfig: config,
		Signer:        signer,
	}, nil
}

func CreateDfnsAPIClient(options *DfnsAPIOptions) *http.Client {
	return &http.Client{
		Transport: dfnsapi.NewAuthTransport(
			&dfnsapi.AuthTransportConfig{
				AppID:     options.AppID,
				AuthToken: options.AuthToken,
				BaseURL:   options.BaseURL,
				Signer:    options.Signer,
			},
		),
	}
}
