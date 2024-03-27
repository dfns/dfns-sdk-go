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
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/dfns/dfns-sdk-go/internal/credentials"
)

func TestPerformSimpleRequest(t *testing.T) {
	t.Parallel()

	authToken := "your-auth-token" //nolint:gosec // This is a test

	config := &AuthTransportConfig{
		AppID:     "your-app-id",
		AuthToken: &authToken,
		BaseURL:   "https://your.api.endpoint",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkBasicHeaders(t, r, config)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "success"}`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	httpClient := createHttpClient(config)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/some-path", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}
func TestPerformSimpleRequest_Error(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name               string
		statusCode         int
		response           string
		expectedErrMessage string
	}{
		{
			name:               "Error",
			statusCode:         400,
			response:           `{"error":{"message": "aie"}}`,
			expectedErrMessage: "aie",
		},
		{
			name:               "UnknownError",
			statusCode:         400,
			response:           `{"body": "aie"}`,
			expectedErrMessage: "Unknown error",
		},
		{
			name:               "PolicyPendingError",
			statusCode:         202,
			response:           `{"message": "policy pending!"}`,
			expectedErrMessage: "Operation triggered a policy pending approval",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			authToken := "your-auth-token" //nolint:gosec // This is a test

			config := &AuthTransportConfig{
				AppID:     "your-app-id",
				AuthToken: &authToken,
				BaseURL:   "https://your.api.endpoint",
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				checkBasicHeaders(t, r, config)
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.response))
			})

			server := httptest.NewServer(handler)
			defer server.Close()

			httpClient := createHttpClient(config)

			req, err := http.NewRequest(http.MethodGet, server.URL+"/some-path", nil)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := httpClient.Do(req)

			var (
				dfnsErr *DfnsError
				ok      bool
			)

			if tc.statusCode == 202 {
				policyErr, castOk := errors.Unwrap(err).(*PolicyPendingError)
				if castOk {
					dfnsErr, ok = &policyErr.DfnsError, castOk
				}
			} else {
				dfnsErr, ok = errors.Unwrap(err).(*DfnsError)
			}

			if !ok {
				t.Fatalf("error is not of type DfnsError: %v", err)
			}

			if dfnsErr.Message != tc.expectedErrMessage {
				t.Errorf("expected error message %q, got %q", tc.expectedErrMessage, dfnsErr.Message)
			}

			if dfnsErr.HTTPStatus != tc.statusCode {
				t.Errorf("expected HTTP status code %d, got %d", tc.statusCode, dfnsErr.HTTPStatus)
			}

			if err == nil {
				resp.Body.Close()
			}
		})
	}
}

func TestPerformUserActionRequest_ParseAuthHeader_Error(t *testing.T) {
	t.Parallel()

	authToken := "your-auth-token" //nolint:gosec // This is a test

	config := &AuthTransportConfig{
		AppID:     "your-app-id",
		AuthToken: &authToken,
		BaseURL:   "https://your.api.endpoint",
	}

	httpClient := createHttpClient(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/some-path", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set(UserActionHeader, "toto")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if err != nil {
		t.Error("expected error when parsing auth header but got nil")
	}
}

func TestPerformUserActionRequest(t *testing.T) {
	t.Parallel()

	authToken := "your-auth-token" //nolint:gosec // This is a test
	challenge := "challenge"
	challengeIdentifier := "challengeIdentifier"
	credID := "credId"
	appOrigin := "appOrigin"
	userAction := "userAction"

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey)})

	signer := createRSASigner(string(rsaPrivateKeyPEM), credID, appOrigin)

	config := &AuthTransportConfig{
		AppID:     "your-app-id",
		AuthToken: &authToken,
		Signer:    signer,
	}

	body := []byte(`{"network": "eth"}`)

	// Creating HTTP test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/action/init":
			checkBasicHeaders(t, r, config)

			expectedBody := createUserActionChallengeRequest{
				UserActionPayload:    string(body),
				UserActionHTTPMethod: "POST",
				UserActionHTTPPath:   "/some-path",
				UserActionServerKind: "Api",
			}

			checkJSONRequest(t, r, expectedBody)

			response := createUserActionChallengeResponse{
				Challenge:           challenge,
				ChallengeIdentifier: challengeIdentifier,
				AllowCredentials:    nil,
			}

			respBody, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}

			w.WriteHeader(http.StatusOK)
			w.Write(respBody)

		case "/auth/action":
			checkBasicHeaders(t, r, config)

			assertion, err := config.Signer.Sign(challenge, nil)
			if err != nil {
				t.Fatal(err)
			}

			expectedBody := signUserActionChallengeRequest{
				ChallengeIdentifier: challengeIdentifier,
				FirstFactor:         assertion,
			}

			checkJSONRequest(t, r, expectedBody)

			response := signUserActionResponse{
				UserAction: userAction,
			}

			respBody, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}

			w.WriteHeader(http.StatusOK)
			w.Write(respBody)

		case "/some-path":
			checkBasicHeaders(t, r, config)

			if r.Header.Get("x-dfns-useraction") != userAction {
				t.Errorf("Unexpected value for x-dfns-useraction header: expected %s, got %s", userAction, r.Header.Get("x-dfns-useraction"))
			}

			// Return a mock response
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success"}`))

		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer ts.Close()

	config.BaseURL = ts.URL

	httpClient := createHttpClient(config)

	req, err := http.NewRequest("POST", ts.URL+"/some-path", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Unexpected status code: expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func checkJSONRequest[T any](t *testing.T, r *http.Request, expected T) {
	t.Helper()

	var reqBody T
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, reqBody) {
		t.Errorf("Unexpected request body: expected %v, got %v", expected, reqBody)
	}
}

func checkBasicHeaders(t *testing.T, req *http.Request, config *AuthTransportConfig) {
	t.Helper()

	if got, want := req.Header.Get("x-dfns-appid"), config.AppID; got != want {
		t.Errorf("appid header = %q; want %q", got, want)
	}
	if got := req.Header.Get("x-dfns-nonce"); got == "" {
		t.Error("nonce header is empty")
	}
	if got, want := req.Header.Get("authorization"), "Bearer "+*config.AuthToken; got != want {
		t.Errorf("authorization header = %q; want %q", got, want)
	}
	if got, want := req.Header.Get("Content-Type"), "application/json"; got != want {
		t.Errorf("Content-Type header = %q; want %q", got, want)
	}
}

func createHttpClient(config *AuthTransportConfig) *http.Client {
	return &http.Client{
		Transport: NewAuthTransport(config),
	}
}

type simpleRSASigner struct {
	privateKey string
	credID     string
	appOrigin  string
}

func (s *simpleRSASigner) Sign(challenge string, allowCredentials *credentials.AllowCredentials,
) (*credentials.KeyAssertion, error) {

	return &credentials.KeyAssertion{}, nil
}

func createRSASigner(privateKey, credID, appOrigin string) *simpleRSASigner {
	return &simpleRSASigner{
		privateKey,
		credID,
		appOrigin,
	}
}
