package dfnsapiclient

import (
	"errors"
	"net/http"

	"github.com/dfns/dfns-sdk-go/internal/credentials"
	dfnsapi "github.com/dfns/dfns-sdk-go/internal/dfnsapiclient"
)

var errBaseURLEmpty = errors.New("BaseUrl cannot be empty")

// DfnsAPIConfig defines the configuration options to connect
// the DFNS API.
type DfnsAPIConfig struct {
	// The Dfns organisation ID (optional)
	OrgID *string
	// The authentication token
	AuthToken *string
	// The base URL of the DFNS API
	BaseURL string
	// The base Auth URL of the DFNS API (optional)
	BaseAuthURL *string
	// The kind of server to perform user actions against (optional, default is "Api")
	UserActionServerKind *string
}

// DfnsAPIOptions contains all the information needed for
// authentication with DFNS.
type DfnsAPIOptions struct {
	// Configuration to connect the DFNS API
	*DfnsAPIConfig
	// The credential signer for signing user actions
	Signer credentials.ICredentialSigner
}

// NewDfnsAPIOptions creates a new DfnsApiOptions instance with the provided parameters.
func NewDfnsAPIOptions(config *DfnsAPIConfig, signer credentials.ICredentialSigner) (*DfnsAPIOptions, error) {
	if config.BaseURL == "" {
		return nil, errBaseURLEmpty
	}

	return &DfnsAPIOptions{
		DfnsAPIConfig: config,
		Signer:        signer,
	}, nil
}

// CreateDfnsAPIClient creates a new HTTP client with integrated
// DFNS authentication capabilities. The client automatically adds
// all required authentication headers to outgoing requests and, if necessary,
// performs challenge signature exchanges.
// Special care should be taken when configuring the HTTP transport layer to ensure
// that any customizations do not interfere with the authentication mechanism.
// Removing required headers or altering the behavior of the transport could
// disrupt the authentication process.
//
// Example usage:
//
//	options := NewDfnsAPIOptions(config, signer)
//
//	client := CreateDfnsAPIClient(options)
//
//	resp, err := client.Post("https://api.example.com/resource", ....)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	defer resp.Body.Close()
//	// Process response...
func CreateDfnsAPIClient(options *DfnsAPIOptions) *http.Client {
	return &http.Client{
		Transport: dfnsapi.NewAuthTransport(
			&dfnsapi.AuthTransportConfig{
				OrgID:                options.OrgID,
				AuthToken:            options.AuthToken,
				BaseURL:              options.BaseURL,
				BaseAuthURL:          options.BaseAuthURL,
				UserActionServerKind: options.UserActionServerKind,
				Signer:               options.Signer,
			},
		),
	}
}
