package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dfns/dfns-sdk-go/signer"
)

// mockSigner implements signer.Signer for testing.
type mockSigner struct {
	signFn func(*signer.UserActionChallenge) (*signer.CredentialAssertion, error)
}

func (m *mockSigner) Sign(c *signer.UserActionChallenge) (*signer.CredentialAssertion, error) {
	return m.signFn(c)
}

func newTestClient(t *testing.T, server *httptest.Server, s signer.Signer) *Client {
	t.Helper()

	c, err := New(Options{
		BaseURL:    server.URL,
		AuthToken:  "test-token",
		Signer:     s,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}

	return c
}

// --- Tests for New() ---

func TestNew_EmptyAuthToken(t *testing.T) {
	t.Parallel()

	_, err := New(Options{BaseURL: "https://example.com", AuthToken: ""})
	if err == nil || !strings.Contains(err.Error(), "AuthToken is required") {
		t.Fatalf("expected AuthToken error, got: %v", err)
	}
}

func TestNew_HTTPSchemeRejected(t *testing.T) {
	t.Parallel()

	_, err := New(Options{BaseURL: "http://example.com", AuthToken: "token"})
	if err == nil || !strings.Contains(err.Error(), "BaseURL must use https scheme") {
		t.Fatalf("expected https scheme error, got: %v", err)
	}
}

func TestNew_InvalidURL(t *testing.T) {
	t.Parallel()

	_, err := New(Options{BaseURL: "://bad", AuthToken: "token"})
	if err == nil || !strings.Contains(err.Error(), "invalid BaseURL") {
		t.Fatalf("expected invalid URL error, got: %v", err)
	}
}

func TestNew_ValidHTTPS(t *testing.T) {
	t.Parallel()

	c, err := New(Options{BaseURL: "https://example.com", AuthToken: "token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNew_DefaultBaseURL(t *testing.T) {
	t.Parallel()

	c, err := New(Options{AuthToken: "token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.opts.BaseURL != "https://api.dfns.io" {
		t.Fatalf("expected default BaseURL, got %s", c.opts.BaseURL)
	}
}

func TestNew_CustomHTTPClient(t *testing.T) {
	t.Parallel()

	custom := &http.Client{}

	c, err := New(Options{BaseURL: "https://example.com", AuthToken: "token", HTTPClient: custom})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.httpClient != custom {
		t.Fatal("expected custom HTTP client to be used")
	}
}

// --- Tests for Do() ---

func TestDo_GET_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"id": "123"})
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	var result struct {
		ID string `json:"id"`
	}

	err := c.Do(context.Background(), "GET", "/test", nil, &result, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID != "123" {
		t.Fatalf("expected id=123, got %s", result.ID)
	}
}

func TestDo_POST_WithBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization Bearer test-token, got %s", r.Header.Get("Authorization"))
		}

		body, _ := io.ReadAll(r.Body)

		var reqBody map[string]string

		json.Unmarshal(body, &reqBody)

		if reqBody["name"] != "test" {
			t.Errorf("expected name=test in body, got %s", reqBody["name"])
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	var result struct {
		OK bool `json:"ok"`
	}

	err := c.Do(context.Background(), "POST", "/test", map[string]string{"name": "test"}, &result, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.OK {
		t.Fatal("expected ok=true")
	}
}

func TestDo_NilBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("expected empty body, got %s", string(body))
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	err := c.Do(context.Background(), "GET", "/test", nil, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDo_NilResult(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data":"ignored"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	err := c.Do(context.Background(), "GET", "/test", nil, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDo_EmptyResponseBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	var result struct{ ID string }

	err := c.Do(context.Background(), "GET", "/test", nil, &result, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID != "" {
		t.Fatalf("expected empty result, got %s", result.ID)
	}
}

func TestDo_APIError_400(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	err := c.Do(context.Background(), "GET", "/test", nil, nil, false)
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}

	if apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", apiErr.StatusCode)
	}

	if !strings.Contains(apiErr.Body, "bad request") {
		t.Fatalf("expected body to contain 'bad request', got %s", apiErr.Body)
	}
}

func TestDo_APIError_500(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	err := c.Do(context.Background(), "GET", "/test", nil, nil, false)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}

	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", apiErr.StatusCode)
	}
}

func TestDo_InvalidJSONResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	var result struct{ ID string }

	err := c.Do(context.Background(), "GET", "/test", nil, &result, false)
	if err == nil || !strings.Contains(err.Error(), "failed to unmarshal response") {
		t.Fatalf("expected unmarshal error, got: %v", err)
	}
}

func TestDo_MarshalError(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	err := c.Do(context.Background(), "POST", "/test", math.Inf(1), nil, false)

	if err == nil || !strings.Contains(err.Error(), "failed to marshal request body") {
		t.Fatalf("expected marshal error, got: %v", err)
	}
}

func TestDo_ContextCanceled(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := c.Do(ctx, "GET", "/test", nil, nil, false)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

// --- Tests for signing flow ---

func TestDo_RequiresSignature_NoSigner(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	err := c.Do(context.Background(), "POST", "/test", nil, nil, true)

	if err == nil || !strings.Contains(err.Error(), "signer is required for this operation") {
		t.Fatalf("expected signer error, got: %v", err)
	}
}

func TestDo_RequiresSignature_FullFlow(t *testing.T) {
	t.Parallel()

	var gotUserActionHeader string

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/action/init", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signer.UserActionChallenge{
			ChallengeIdentifier: "challenge-123",
			Challenge:           "dGVzdC1jaGFsbGVuZ2U",
		})
	})
	mux.HandleFunc("/auth/action", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"userAction":"user-action-token-xyz"}`))
	})
	mux.HandleFunc("/test/endpoint", func(w http.ResponseWriter, r *http.Request) {
		gotUserActionHeader = r.Header.Get("X-DFNS-USERACTION")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":"ok"}`))
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ms := &mockSigner{
		signFn: func(c *signer.UserActionChallenge) (*signer.CredentialAssertion, error) {
			if c.ChallengeIdentifier != "challenge-123" {
				t.Errorf("expected challenge-123, got %s", c.ChallengeIdentifier)
			}

			return &signer.CredentialAssertion{
				Kind: "Key",
				CredentialAssertion: signer.CredentialAssertionData{
					CredID:     "cred-1",
					ClientData: "Y2xpZW50LWRhdGE",
					Signature:  "c2lnbmF0dXJl",
				},
			}, nil
		},
	}

	c := newTestClient(t, server, ms)

	var result struct {
		Result string `json:"result"`
	}

	err := c.Do(context.Background(), "POST", "/test/endpoint", map[string]string{"key": "value"}, &result, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotUserActionHeader != "user-action-token-xyz" {
		t.Fatalf("expected X-DFNS-USERACTION=user-action-token-xyz, got %s", gotUserActionHeader)
	}

	if result.Result != "ok" {
		t.Fatalf("expected result=ok, got %s", result.Result)
	}
}

func TestDo_RequiresSignature_ChallengeFailure(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/action/init", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ms := &mockSigner{
		signFn: func(_ *signer.UserActionChallenge) (*signer.CredentialAssertion, error) {
			t.Fatal("signer should not be called when challenge fails")

			return nil, errSignerShouldNotBeCalled
		},
	}

	c := newTestClient(t, server, ms)
	err := c.Do(context.Background(), "POST", "/test", nil, nil, true)

	if err == nil || !strings.Contains(err.Error(), "failed to get user action token") {
		t.Fatalf("expected user action token error, got: %v", err)
	}
}

var errSignerShouldNotBeCalled = errors.New("signer should not be called")

func TestDo_RequiresSignature_SignerError(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/action/init", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signer.UserActionChallenge{
			ChallengeIdentifier: "challenge-123",
			Challenge:           "dGVzdA",
		})
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ms := &mockSigner{
		signFn: func(_ *signer.UserActionChallenge) (*signer.CredentialAssertion, error) {
			return nil, errors.New("signing device unavailable")
		},
	}

	c := newTestClient(t, server, ms)
	err := c.Do(context.Background(), "POST", "/test", nil, nil, true)

	if err == nil || !strings.Contains(err.Error(), "failed to sign challenge") {
		t.Fatalf("expected sign challenge error, got: %v", err)
	}
}

func TestDo_RequiresSignature_CompleteFailure(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/action/init", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signer.UserActionChallenge{
			ChallengeIdentifier: "challenge-123",
			Challenge:           "dGVzdA",
		})
	})
	mux.HandleFunc("/auth/action", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("completion failed"))
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ms := &mockSigner{
		signFn: func(_ *signer.UserActionChallenge) (*signer.CredentialAssertion, error) {
			return &signer.CredentialAssertion{
				Kind: "Key",
				CredentialAssertion: signer.CredentialAssertionData{
					CredID:     "cred-1",
					ClientData: "Y2xpZW50",
					Signature:  "c2ln",
				},
			}, nil
		},
	}

	c := newTestClient(t, server, ms)
	err := c.Do(context.Background(), "POST", "/test", nil, nil, true)

	if err == nil || !strings.Contains(err.Error(), "failed to get user action token") {
		t.Fatalf("expected user action token error, got: %v", err)
	}
}

func TestDo_NewRequestError(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	// An invalid HTTP method (containing a space) causes NewRequestWithContext to fail.
	err := c.Do(context.Background(), "BAD METHOD", "/test", nil, nil, false)
	if err == nil || !strings.Contains(err.Error(), "failed to create request") {
		t.Fatalf("expected failed to create request error, got: %v", err)
	}
}

// --- Tests for APIError ---

func TestAPIError_Error(t *testing.T) {
	t.Parallel()

	e := &APIError{StatusCode: 404, Body: "not found"}

	expected := "API error (status 404): not found"
	if e.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, e.Error())
	}
}
