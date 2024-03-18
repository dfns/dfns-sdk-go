package dfns_api_client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"

	"github.com/dfns/dfns-sdk-go/pkg/credentials"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerformSimpleRequest(t *testing.T) {
	appID := "your-app-id"
	authToken := "your-auth-token"
	baseURL := "https://your.api.endpoint"

	apiOptions := &DfnsApiOptions{
		DfnsApiConfig: &DfnsApiConfig{
			AppId:     appID,
			AuthToken: &authToken,
			BaseUrl:   baseURL,
		},
		Signer: nil,
	}

	httpClient := CreateDfnsApiClient(apiOptions)

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	req, err := http.NewRequest("GET", "https://your.api.endpoint/some-path", nil)
	assert.NoError(t, err)

	httpmock.RegisterResponder("GET", "https://your.api.endpoint/some-path",
		func(req *http.Request) (*http.Response, error) {
			checkBasicHeaders(t, req, apiOptions)

			resp := httpmock.NewStringResponse(200, `{"status": "success"}`)

			return resp, nil
		})

	resp, err := httpClient.Do(req)
	require.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode)
}

func TestPerformSimpleRequest_Error(t *testing.T) {
	testCases := []struct {
		name               string
		statusCode         int
		response           string
		expectedErrMessage string
	}{
		{
			name:               "Error",
			statusCode:         400,
			response:           `{"message": "aie"}`,
			expectedErrMessage: "aie",
		},
		{
			name:               "PolicyPendingError",
			statusCode:         202,
			response:           `{"message": "policy pending!"}`,
			expectedErrMessage: "Operation triggered a policy pending approval",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			appID := "your-app-id"
			authToken := "your-auth-token"
			baseURL := "https://your.api.endpoint"

			apiOptions := &DfnsApiOptions{
				DfnsApiConfig: &DfnsApiConfig{
					AppId:     appID,
					AuthToken: &authToken,
					BaseUrl:   baseURL,
				},
				Signer: nil,
			}

			httpClient := CreateDfnsApiClient(apiOptions)

			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

			req, err := http.NewRequest("GET", "https://your.api.endpoint/some-path", nil)
			assert.NoError(t, err)

			httpmock.RegisterResponder("GET", "https://your.api.endpoint/some-path",
				func(req *http.Request) (*http.Response, error) {
					checkBasicHeaders(t, req, apiOptions)

					resp := httpmock.NewStringResponse(tc.statusCode, tc.response)

					return resp, nil
				})

			_, err = httpClient.Do(req)
			require.Error(t, err)

			var dfnsErr *DfnsError
			var ok bool

			if tc.statusCode == 202 {
				policyErr, castOk := errors.Unwrap(err).(*PolicyPendingError)
				if castOk {
					dfnsErr, ok = &policyErr.DfnsError, castOk
				}
			} else {
				dfnsErr, ok = errors.Unwrap(err).(*DfnsError)
			}

			require.True(t, ok)
			assert.Equal(t, dfnsErr.Message, tc.expectedErrMessage)
			assert.Equal(t, dfnsErr.HttpStatus, tc.statusCode)
		})
	}
}

func TestPerformUserActionRequest(t *testing.T) {
	appID := "appId"
	authToken := "authToken"
	baseURL := "https://your.api.endpoint"
	challenge := "challenge"
	challengeIdentifier := "challengeIdentifier"
	credId := "credId"
	appOrigin := "appOrigin"
	userAction := "userAction"

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey)})

	conf := &credentials.AsymmetricKeySignerConfig{
		PrivateKey: string(rsaPrivateKeyPEM),
		CredId:     credId,
		AppOrigin:  appOrigin,
	}

	signer := credentials.NewAsymmetricKeySigner(conf)

	apiOptions := &DfnsApiOptions{
		DfnsApiConfig: &DfnsApiConfig{
			AppId:     appID,
			AuthToken: &authToken,
			BaseUrl:   baseURL,
		},
		Signer: signer,
	}

	httpClient := CreateDfnsApiClient(apiOptions)

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	body := []byte(`{"network": "eth"}`)

	req, err := http.NewRequest("POST", "https://your.api.endpoint/some-path", bytes.NewReader(body))
	assert.NoError(t, err)

	httpmock.RegisterResponder("POST", "https://your.api.endpoint/auth/action/init",
		func(req *http.Request) (*http.Response, error) {
			checkBasicHeaders(t, req, apiOptions)

			expectedBody := createUserActionChallengeRequest{
				UserActionPayload:    string(body),
				UserActionHttpMethod: "POST",
				UserActionHttpPath:   "/some-path",
				UserActionServerKind: "Api",
			}

			var reqBody createUserActionChallengeRequest
			err = json.NewDecoder(req.Body).Decode(&reqBody)
			assert.NoError(t, err)

			assert.Equal(t, expectedBody, reqBody)

			response := createUserActionChallengeResponse{
				Challenge:           challenge,
				ChallengeIdentifier: challengeIdentifier,
				AllowCredentials:    nil,
			}

			respBody, err := json.Marshal(response)
			assert.NoError(t, err)

			resp := httpmock.NewBytesResponse(200, respBody)

			return resp, nil
		})

	httpmock.RegisterResponder("POST", "https://your.api.endpoint/auth/action",
		func(req *http.Request) (*http.Response, error) {
			checkBasicHeaders(t, req, apiOptions)

			assertion, err := apiOptions.Signer.Sign(challenge, nil)
			assert.NoError(t, err)

			expectedBody := signUserActionChallengeRequest{
				ChallengeIdentifier: challengeIdentifier,
				FirstFactor:         assertion,
			}

			var reqBody signUserActionChallengeRequest
			err = json.NewDecoder(req.Body).Decode(&reqBody)
			assert.NoError(t, err)

			assert.Equal(t, expectedBody, reqBody)

			response := signUserActionResponse{
				UserAction: userAction,
			}

			respBody, err := json.Marshal(response)
			assert.NoError(t, err)

			resp := httpmock.NewBytesResponse(200, respBody)

			return resp, nil
		})

	httpmock.RegisterResponder("POST", "https://your.api.endpoint/some-path",
		func(req *http.Request) (*http.Response, error) {
			checkBasicHeaders(t, req, apiOptions)

			assert.Equal(t, userAction, req.Header.Get("x-dfns-useraction"))

			// Return a mock response
			resp := httpmock.NewStringResponse(200, `{"status": "success"}`)

			return resp, nil
		})

	resp, err := httpClient.Do(req)
	assert.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode)
}

func checkBasicHeaders(t *testing.T, req *http.Request, option *DfnsApiOptions) {
	assert.Equal(t, option.AppId, req.Header.Get("x-dfns-appid"))
	assert.NotEmpty(t, req.Header.Get("x-dfns-nonce")) // Check for non-empty nonce
	assert.Equal(t, "Bearer "+*option.AuthToken, req.Header.Get("authorization"))
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
}
