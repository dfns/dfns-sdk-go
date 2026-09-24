package exchanges

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dfns/dfns-sdk-go/v2/internal/client"
	"github.com/dfns/dfns-sdk-go/v2/signer"
)

// mockSigner satisfies signer.Signer for the user-action signing flow that write
// endpoints (CreateDeposit requires a signature) run before issuing the request.
type mockSigner struct{}

func (mockSigner) Sign(_ *signer.UserActionChallenge) (*signer.CredentialAssertion, error) {
	return &signer.CredentialAssertion{
		Kind: "Key",
		CredentialAssertion: signer.CredentialAssertionData{
			CredID:     "cred-1",
			ClientData: "client-data",
			Signature:  "signature",
		},
	}, nil
}

// recordedRequest captures the parts of an outgoing HTTP request we assert on.
type recordedRequest struct {
	method string
	path   string
	body   string
}

// newRecordingClient returns a TLS-backed ExchangesClient plus a pointer to a slice
// that records every request hitting the exchange deposit endpoint. Requests to the
// user-action signing endpoints are answered but not recorded, so the slice holds
// exactly the endpoint calls we care about (canonical vs deprecated alias).
func newRecordingClient(t *testing.T, recorded *[]recordedRequest) *ExchangesClient {
	t.Helper()

	mux := http.NewServeMux()

	// User-action signing handshake (POST /auth/action/init then POST /auth/action).
	mux.HandleFunc("/auth/action/init", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"challengeIdentifier": "challenge-1",
			"challenge":           "challenge-value",
			"allowCredentials":    map[string]any{"key": []any{}, "webauthn": []any{}},
		})
	})
	mux.HandleFunc("/auth/action", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"userAction": "user-action-token"})
	})

	// The actual endpoint under test. Record what the SDK sent, then return a
	// minimal valid CreateDepositResponse.
	mux.HandleFunc("/exchanges/ex-1/accounts/acc-1/deposits", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*recorded = append(*recorded, recordedRequest{
			method: r.Method,
			path:   r.URL.Path,
			body:   string(body),
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         "dp-1",
			"exchangeId": "ex-1",
			"accountId":  "acc-1",
			"kind":       "Deposit",
			"walletId":   "wa-1",
		})
	})

	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	c, err := client.New(client.Options{
		BaseURL:    server.URL,
		AuthToken:  "test-token",
		Signer:     mockSigner{},
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	return NewExchangesClient(c)
}

// TestDeprecatedAlias_CreateExchangeDeposit_ForwardsToCanonical asserts that the
// @deprecated alias CreateExchangeDeposit issues the exact same HTTP request
// (method + path + body) as the canonical CreateDeposit method it forwards to.
//
// This guards the operationId-rename compat layer: the generator emits a canonical
// method plus a deprecated forwarding alias, and callers on the old name must keep
// hitting the same endpoint.
func TestDeprecatedAlias_CreateExchangeDeposit_ForwardsToCanonical(t *testing.T) {
	t.Parallel()

	var recorded []recordedRequest

	c := newRecordingClient(t, &recorded)

	ctx := context.Background()
	body := map[string]any{"asset": "USDC", "amount": "100", "kind": "Native"}

	// Canonical method.
	if _, err := c.CreateDeposit(ctx, "ex-1", "acc-1", body); err != nil {
		t.Fatalf("CreateDeposit returned error: %v", err)
	}

	// Deprecated alias — same arguments.
	if _, err := c.CreateExchangeDeposit(ctx, "ex-1", "acc-1", body); err != nil {
		t.Fatalf("CreateExchangeDeposit (deprecated alias) returned error: %v", err)
	}

	if len(recorded) != 2 {
		t.Fatalf("expected 2 recorded endpoint requests, got %d", len(recorded))
	}

	canonical, alias := recorded[0], recorded[1]

	if alias.method != canonical.method {
		t.Errorf("method mismatch: canonical %q, alias %q", canonical.method, alias.method)
	}

	if alias.path != canonical.path {
		t.Errorf("path mismatch: canonical %q, alias %q", canonical.path, alias.path)
	}

	if alias.body != canonical.body {
		t.Errorf("body mismatch: canonical %q, alias %q", canonical.body, alias.body)
	}

	// Sanity: the recorded request is the one we expect (not, say, a signing call).
	if canonical.method != http.MethodPost {
		t.Errorf("expected POST, got %q", canonical.method)
	}

	if canonical.path != "/exchanges/ex-1/accounts/acc-1/deposits" {
		t.Errorf("unexpected path %q", canonical.path)
	}
}
