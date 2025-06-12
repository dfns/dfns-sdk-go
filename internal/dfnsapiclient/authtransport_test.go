package dfnsapiclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dfns/dfns-sdk-go/internal/credentials"
)

const (
	testOrgID     = "org-id"
	testAuthToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwczovL2N1c3RvbS9hcHBfbWV0YWRhdGEiOnsib3JnSWQiOiJvcmctaWQifX0.xxx" //nolint:gosec // test
)

func TestPerformSimpleRequest(t *testing.T) {
	t.Parallel()

	performSimpleRequest(t, http.MethodGet, "")
}

func TestPerformSimpleRequest_With_POST(t *testing.T) {
	t.Parallel()

	performSimpleRequest(t, http.MethodPost, "false")
}

func performSimpleRequest(t *testing.T, method, userActionHeader string) {
	t.Helper()

	authToken := testAuthToken

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
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

	httpClient := createHTTPClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, server.URL+"/some-path", nil)
	if err != nil {
		t.Fatal(err)
	}

	if userActionHeader != "" {
		req.Header.Set(UserActionHeader, userActionHeader)
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

func TestPerformRequest_WrongAuthToken(t *testing.T) {
	t.Parallel()

	authToken := "bad-token"

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
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

	httpClient := createHTTPClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/some-path", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = httpClient.Do(req)

	if err == nil {
		t.Fatal("Expected an http error but got nil")
	}
}

func TestPerformRequest_Error(t *testing.T) {
	t.Parallel()

	authToken := testAuthToken

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
		AuthToken: &authToken,
		BaseURL:   "https://your.api.endpoint",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	httpClient := createHTTPClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/some-path", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = httpClient.Do(req)
	if err == nil {
		t.Fatal("Expected an http error but got nil")
	}
}

func TestPerformRequest_Response_Error(t *testing.T) {
	t.Parallel()

	authToken := testAuthToken

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
		AuthToken: &authToken,
		BaseURL:   "https://your.api.endpoint",
	}

	testCases := []struct {
		name               string
		statusCode         int
		response           io.Reader
		expectedErrMessage string
		shouldBeDFNSError  bool
	}{
		{
			name:               "Error with response body containing error message",
			statusCode:         400,
			response:           strings.NewReader(`{"error":{"message": "aie"}}`),
			expectedErrMessage: "aie",
			shouldBeDFNSError:  true,
		},
		{
			name:               "Error with response body containing message",
			statusCode:         400,
			response:           strings.NewReader(`{"message": "aie"}`),
			expectedErrMessage: "aie",
			shouldBeDFNSError:  true,
		},
		{
			name:               "UnknownError with response body containing unknown error",
			statusCode:         400,
			response:           strings.NewReader(`{"body": "aie"}`),
			expectedErrMessage: "Unknown error",
			shouldBeDFNSError:  true,
		},
		{
			name:               "PolicyPendingError with response body containing policy pending message",
			statusCode:         202,
			response:           strings.NewReader(`{"message": "policy pending!"}`),
			expectedErrMessage: "Operation triggered a policy pending approval",
			shouldBeDFNSError:  true,
		},
		{
			name:               "Error with mock unmarshal error",
			statusCode:         400,
			response:           MockUnmarshalError{},
			expectedErrMessage: "unexpected end of JSON input",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				checkBasicHeaders(t, r, config)
				w.WriteHeader(tc.statusCode)

				_, err := io.Copy(w, tc.response)
				if err != nil {
					t.Fatalf("Error when building the handler func %s", err)
				}
			})

			server := httptest.NewServer(handler)
			defer server.Close()

			httpClient := createHTTPClient(config)

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/some-path", nil)
			if err != nil {
				t.Fatal(err)
			}

			_, err = httpClient.Do(req)
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}

			var (
				dfnsErr *DfnsError
				ok      bool
			)

			if tc.statusCode == 202 {
				policyErr, castOk := errors.Unwrap(err).(*PolicyPendingError)
				if castOk {
					dfnsErr, ok = &policyErr.DfnsError, castOk
				}
			} else if tc.shouldBeDFNSError {
				dfnsErr, ok = errors.Unwrap(err).(*DfnsError)
			}

			if tc.shouldBeDFNSError {
				if !ok {
					t.Fatalf("error is not of type DfnsError: %v", err)
				}

				if dfnsErr.Message != tc.expectedErrMessage {
					t.Errorf("expected error message %q, got %q", tc.expectedErrMessage, dfnsErr.Message)
				}

				if dfnsErr.HTTPStatus != tc.statusCode {
					t.Errorf("expected HTTP status code %d, got %d", tc.statusCode, dfnsErr.HTTPStatus)
				}
			} else if !strings.Contains(errors.Unwrap(err).Error(), tc.expectedErrMessage) {
				t.Errorf("expected error containing %s, got %s", tc.expectedErrMessage, err.Error())
			}
		})
	}
}

func TestPerformUserActionRequest_ParseAuthHeader_Error(t *testing.T) {
	t.Parallel()

	authToken := testAuthToken

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
		AuthToken: &authToken,
		BaseURL:   "https://your.api.endpoint",
	}

	httpClient := createHTTPClient(config)

	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	server := httptest.NewServer(handler)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/some-path", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set(UserActionHeader, "toto")

	_, err = httpClient.Do(req)
	if err == nil {
		t.Fatal("expected error when parsing auth header but got nil")
	}
}

func TestPerformUserActionRequest(t *testing.T) {
	t.Parallel()

	authToken := testAuthToken
	challenge := "challenge"
	challengeIdentifier := "challengeIdentifier"
	userAction := "userAction"

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey)})

	signer := createMockSigner(string(rsaPrivateKeyPEM))

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
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

			respBody, marchalErr := json.Marshal(response)
			if marchalErr != nil {
				t.Fatal(marchalErr)
			}

			w.WriteHeader(http.StatusOK)
			w.Write(respBody)

		case "/auth/action":
			checkBasicHeaders(t, r, config)

			assertion, signErr := config.Signer.Sign(context.Background(), nil)
			if signErr != nil {
				t.Fatal(signErr)
			}

			expectedBody := signUserActionChallengeRequest{
				ChallengeIdentifier: challengeIdentifier,
				FirstFactor:         assertion,
			}

			checkJSONRequest(t, r, expectedBody)

			response := signUserActionResponse{
				UserAction: userAction,
			}

			respBody, marchalErr := json.Marshal(response)
			if marchalErr != nil {
				t.Fatal(marchalErr)
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

	httpClient := createHTTPClient(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/some-path", bytes.NewReader(body))
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

func TestPerformUserActionRequest_CreateChallenge_Error(t *testing.T) {
	t.Parallel()

	authToken := testAuthToken

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
		AuthToken: &authToken,
		Signer:    &ErrorSigner{},
	}

	body := []byte(`{"network": "eth"}`)

	httpClient := createHTTPClient(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/some-path", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	_, err = httpClient.Do(req)
	if err == nil {
		t.Fatalf("Expected http error but got nil")
	}
}

func TestPerformUserActionRequest_CreateChallenge_UnmarshallError(t *testing.T) {
	t.Parallel()

	authToken := testAuthToken

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey)})

	signer := createMockSigner(string(rsaPrivateKeyPEM))

	// Creating HTTP test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.Copy(w, MockUnmarshalError{})
	}))
	defer ts.Close()

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
		AuthToken: &authToken,
		Signer:    signer,
		BaseURL:   ts.URL,
	}

	httpClient := createHTTPClient(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	body := []byte(`{"network": "eth"}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/some-path", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	_, err = httpClient.Do(req)
	if !strings.Contains(err.Error(), "couldn't unmarshal challenge response: unexpected end of JSON input") {
		t.Fatalf("Expected marshall error but got %s", err)
	}
}

func TestPerformUserActionRequest_Signer_Error(t *testing.T) {
	t.Parallel()

	authToken := testAuthToken
	challenge := "challenge"
	challengeIdentifier := "challengeIdentifier"

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
		AuthToken: &authToken,
		Signer:    &ErrorSigner{},
	}

	body := []byte(`{"network": "eth"}`)

	// Creating HTTP test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		respBody, marchalErr := json.Marshal(response)
		if marchalErr != nil {
			t.Fatal(marchalErr)
		}

		w.WriteHeader(http.StatusOK)
		w.Write(respBody)
	}))
	defer ts.Close()

	config.BaseURL = ts.URL

	httpClient := createHTTPClient(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/some-path", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	_, err = httpClient.Do(req)
	if errors.Unwrap(err).Error() != fmt.Sprintf("error signing the user challenge: %s", errSigner) {
		t.Fatalf("Expected signer error but got %s", err)
	}
}

func TestPerformUserActionRequest_SignChallenge_Error(t *testing.T) {
	t.Parallel()

	authToken := testAuthToken
	challenge := "challenge"
	challengeIdentifier := "challengeIdentifier"

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey)})

	signer := createMockSigner(string(rsaPrivateKeyPEM))

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
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

			respBody, marchalErr := json.Marshal(response)
			if marchalErr != nil {
				t.Fatal(marchalErr)
			}

			w.WriteHeader(http.StatusOK)
			w.Write(respBody)

		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer ts.Close()

	config.BaseURL = ts.URL

	httpClient := createHTTPClient(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/some-path", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	_, err = httpClient.Do(req)
	if err == nil {
		t.Fatal(err)
	}
}

func TestPerformUserActionRequest_SignChallenge_UnmarshallError(t *testing.T) {
	t.Parallel()

	authToken := testAuthToken
	challenge := "challenge"
	challengeIdentifier := "challengeIdentifier"

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey)})

	signer := createMockSigner(string(rsaPrivateKeyPEM))

	config := &AuthTransportConfig{
		OrgID:     testOrgID,
		AuthToken: &authToken,
		Signer:    signer,
	}

	body := []byte(`{"network": "eth"}`)

	// Creating HTTP test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/action/init":
			response := createUserActionChallengeResponse{
				Challenge:           challenge,
				ChallengeIdentifier: challengeIdentifier,
				AllowCredentials:    nil,
			}

			respBody, marchalErr := json.Marshal(response)
			if marchalErr != nil {
				t.Fatal(marchalErr)
			}

			w.WriteHeader(http.StatusOK)
			w.Write(respBody)

		case "/auth/action":
			io.Copy(w, MockUnmarshalError{})

		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer ts.Close()

	config.BaseURL = ts.URL

	httpClient := createHTTPClient(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/some-path", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	_, err = httpClient.Do(req)
	if !strings.Contains(err.Error(), "couldn't unmarshaling user action response: unexpected end of JSON input") {
		t.Fatalf("Expected marshall error but got %s", err)
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

	if got, want := req.Header.Get("authorization"), "Bearer "+*config.AuthToken; got != want {
		t.Errorf("authorization header = %q; want %q", got, want)
	}

	if got, want := req.Header.Get("Content-Type"), "application/json"; got != want {
		t.Errorf("Content-Type header = %q; want %q", got, want)
	}
}

func createHTTPClient(config *AuthTransportConfig) *http.Client {
	return &http.Client{
		Transport: NewAuthTransport(config),
	}
}

// MockUnmarshalError is a custom type to simulate an error when unmarshaling JSON.
type MockUnmarshalError struct{}

// Read implements the io.Reader interface but always returns an error.
func (m MockUnmarshalError) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

// Simple RSA Signer that returns no error when signing
type mockSigner struct {
	privateKey string
	credID     string
}

func (s *mockSigner) Sign(
	_ context.Context,
	_ *credentials.UserActionChallenge,
) (*credentials.KeyAssertion, error) {
	return &credentials.KeyAssertion{}, nil
}

func createMockSigner(privateKey string) *mockSigner {
	return &mockSigner{
		privateKey,
		"credId",
	}
}

// Signer that always return an error
type ErrorSigner struct{}

var errSigner = errors.New("sign error")

func (s *ErrorSigner) Sign(
	_ context.Context,
	_ *credentials.UserActionChallenge,
) (*credentials.KeyAssertion, error) {
	return nil, errSigner
}
