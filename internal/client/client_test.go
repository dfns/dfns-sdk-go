package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dfns/dfns-sdk-go/v2/signer"
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

// readMultipartParts streams a multipart/form-data request body without
// ParseMultipartForm (which gosec flags as unbounded), returning the "data"
// field and the "file" part's name and bytes.
func readMultipartParts(t *testing.T, r *http.Request) (string, string, []byte) {
	t.Helper()

	var (
		data, fileName string
		fileContent    []byte
	)

	mr, err := r.MultipartReader()
	if err != nil {
		t.Fatalf("failed to read multipart body: %v", err)
	}

	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatalf("failed to read multipart part: %v", err)
		}

		content, _ := io.ReadAll(io.LimitReader(part, 1<<20))

		switch part.FormName() {
		case "data":
			data = string(content)
		case "file":
			fileName = part.FileName()
			fileContent = content
		}
	}

	return data, fileName, fileContent
}

func TestDoMultipart_Success(t *testing.T) {
	t.Parallel()

	fileBytes := []byte("hello-file-contents")
	wantChecksum := sha256.Sum256(fileBytes)

	var (
		gotData, gotFileName string
		gotFileContent       []byte
	)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "multipart/form-data") {
			t.Errorf("expected multipart/form-data Content-Type, got %s", ct)
		}

		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization Bearer test-token, got %s", r.Header.Get("Authorization"))
		}

		gotData, gotFileName, gotFileContent = readMultipartParts(t, r)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	var result struct {
		OK bool `json:"ok"`
	}

	err := c.DoMultipart(context.Background(), "POST", "/upload",
		map[string]string{"network": "Eth"},
		MultipartFile{Bytes: fileBytes, Name: "doc.pdf"},
		&result, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.OK {
		t.Fatal("expected ok=true")
	}

	if gotFileName != "doc.pdf" {
		t.Errorf("expected file name doc.pdf, got %s", gotFileName)
	}

	if string(gotFileContent) != string(fileBytes) {
		t.Errorf("file content mismatch: got %q", gotFileContent)
	}

	// The "data" part must carry the JSON body plus the injected fileChecksum.
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(gotData), &data); err != nil {
		t.Fatalf("data part is not valid JSON: %v", err)
	}

	if data["network"] != "Eth" {
		t.Errorf("expected network=Eth in data part, got %v", data["network"])
	}

	if data["fileChecksum"] != hex.EncodeToString(wantChecksum[:]) {
		t.Errorf("expected fileChecksum %s, got %v", hex.EncodeToString(wantChecksum[:]), data["fileChecksum"])
	}
}

func TestDoMultipart_DefaultFileName(t *testing.T) {
	t.Parallel()

	var gotFileName string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, gotFileName, _ = readMultipartParts(t, r)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	err := c.DoMultipart(context.Background(), "POST", "/upload", nil,
		MultipartFile{Bytes: []byte("x")}, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotFileName != "upload.bin" {
		t.Errorf("expected default file name upload.bin, got %s", gotFileName)
	}
}

func TestDoMultipart_FileNameSanitized(t *testing.T) {
	t.Parallel()

	var gotFileName string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, gotFileName, _ = readMultipartParts(t, r)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	// CR/LF must be stripped to prevent multipart header injection.
	err := c.DoMultipart(context.Background(), "POST", "/upload", nil,
		MultipartFile{Bytes: []byte("x"), Name: "a\r\nb.bin"}, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotFileName != "ab.bin" {
		t.Errorf("expected CR/LF-stripped file name ab.bin, got %q", gotFileName)
	}
}

func TestDoMultipart_RequiresSignature_FullFlow(t *testing.T) {
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
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
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

	err := c.DoMultipart(context.Background(), "POST", "/upload",
		map[string]string{"k": "v"},
		MultipartFile{Bytes: []byte("file-bytes"), Name: "f.bin"},
		&result, true)
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

func TestDoMultipart_RequiresSignature_NoSigner(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("server should not be called when the signer is missing")
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	err := c.DoMultipart(context.Background(), "POST", "/upload", nil,
		MultipartFile{Bytes: []byte("x")}, nil, true)
	if err == nil {
		t.Fatal("expected an error when signature is required but no signer is configured")
	}
}

func TestDoMultipart_APIError(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`bad request`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	err := c.DoMultipart(context.Background(), "POST", "/upload", nil,
		MultipartFile{Bytes: []byte("x")}, nil, false)
	if err == nil {
		t.Fatal("expected an API error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}

	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", apiErr.StatusCode)
	}
}

func TestDoMultipart_BodyMarshalError(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("server should not be called when the body fails to marshal")
	})), nil)

	// A channel cannot be marshalled to JSON.
	err := c.DoMultipart(context.Background(), "POST", "/upload",
		map[string]interface{}{"bad": make(chan int)},
		MultipartFile{Bytes: []byte("x")}, nil, false)
	if err == nil {
		t.Fatal("expected a marshal error for an unmarshalable body")
	}
}

func TestDoMultipart_BodyNotObject(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("server should not be called when the body is not a JSON object")
	})), nil)

	// A non-object body cannot be merged into the "data" map.
	err := c.DoMultipart(context.Background(), "POST", "/upload",
		[]string{"not", "an", "object"},
		MultipartFile{Bytes: []byte("x")}, nil, false)
	if err == nil {
		t.Fatal("expected an error when the body does not unmarshal into an object")
	}
}

func TestDoMultipart_SignerError(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/action/init", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signer.UserActionChallenge{
			ChallengeIdentifier: "challenge-123",
			Challenge:           "dGVzdC1jaGFsbGVuZ2U",
		})
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ms := &mockSigner{
		signFn: func(_ *signer.UserActionChallenge) (*signer.CredentialAssertion, error) {
			return nil, errors.New("signing failed")
		},
	}

	c := newTestClient(t, server, ms)

	err := c.DoMultipart(context.Background(), "POST", "/upload", nil,
		MultipartFile{Bytes: []byte("x")}, nil, true)
	if err == nil {
		t.Fatal("expected an error when the signer fails")
	}
}

func TestDoMultipart_RequestFailed(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before the request is sent → httpClient.Do fails

	err := c.DoMultipart(ctx, "POST", "/upload", nil,
		MultipartFile{Bytes: []byte("x")}, nil, false)
	if err == nil {
		t.Fatal("expected an error when the request fails")
	}
}

func TestDoMultipart_InvalidJSONResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not-valid-json`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	var result struct {
		OK bool `json:"ok"`
	}

	err := c.DoMultipart(context.Background(), "POST", "/upload", nil,
		MultipartFile{Bytes: []byte("x")}, &result, false)
	if err == nil {
		t.Fatal("expected an error when the response is not valid JSON")
	}
}

func TestDoMultipart_InvalidMethod(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("server should not be called when the request cannot be built")
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	// An invalid HTTP method makes http.NewRequestWithContext fail.
	err := c.DoMultipart(context.Background(), "BAD METHOD", "/upload", nil,
		MultipartFile{Bytes: []byte("x")}, nil, false)
	if err == nil {
		t.Fatal("expected an error when the request cannot be built")
	}
}

// rtFunc adapts a function to http.RoundTripper.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// errReadCloser is a response body whose Read always fails.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (errReadCloser) Close() error             { return nil }

func TestDoMultipart_ResponseBodyReadError(t *testing.T) {
	t.Parallel()

	c, err := New(Options{
		BaseURL:   "https://example.com",
		AuthToken: "token",
		HTTPClient: &http.Client{
			Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
				// Drain the request body so the streaming writer goroutine completes.
				_, _ = io.Copy(io.Discard, req.Body)

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       errReadCloser{},
					Header:     make(http.Header),
				}, nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.DoMultipart(context.Background(), "POST", "/upload", nil,
		MultipartFile{Bytes: []byte("x")}, nil, false)
	if err == nil {
		t.Fatal("expected an error when the response body cannot be read")
	}
}

func TestDo_ResponseBodyReadError(t *testing.T) {
	t.Parallel()

	c, err := New(Options{
		BaseURL:   "https://example.com",
		AuthToken: "token",
		HTTPClient: &http.Client{
			Transport: rtFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       errReadCloser{},
					Header:     make(http.Header),
				}, nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.Do(context.Background(), "GET", "/x", nil, nil, false)
	if err == nil {
		t.Fatal("expected an error when the response body cannot be read")
	}
}

// failingMultipartWriter is an io.Writer that fails the Write which first brings
// trigger into the cumulative output (or the very first Write, when trigger is
// empty). It lets writeMultipartBody's error branches be exercised
// deterministically, instead of racing the io.Pipe in DoMultipart's goroutine.
type failingMultipartWriter struct {
	trigger string
	seen    strings.Builder
	done    bool
}

func (w *failingMultipartWriter) Write(p []byte) (int, error) {
	if w.done {
		return 0, errors.New("writer already failed")
	}

	w.seen.Write(p)

	if w.trigger == "" || strings.Contains(w.seen.String(), w.trigger) {
		w.done = true
		return 0, errors.New("simulated write failure")
	}

	return len(p), nil
}

func TestWriteMultipartBody_Errors(t *testing.T) {
	t.Parallel()

	// Each trigger is a marker that appears for the first time in exactly one
	// stage of the multipart body, so failing on it pins down that stage:
	//   ""            -> the data part's first write
	//   name="file"   -> the file part header (CreateFormFile)
	//   FILECONTENT   -> the file content (part.Write)
	//   --\r\n        -> the closing boundary (writer.Close)
	cases := []struct {
		name    string
		trigger string
		wantMsg string
	}{
		{"data part", "", "failed to write data part"},
		{"file part header", `name="file"`, "failed to create file part"},
		{"file content", "FILECONTENT", "failed to write file part"},
		{"finalize", "--\r\n", "failed to finalize multipart body"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := multipart.NewWriter(&failingMultipartWriter{trigger: tc.trigger})

			err := writeMultipartBody(w, []byte("DATA"), "doc.bin", []byte("FILECONTENT"))
			if err == nil {
				t.Fatalf("expected an error for the %q stage", tc.name)
			}

			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

// TestWriteMultipartBody_Success documents the happy path of the helper directly,
// independent of the streaming goroutine.
func TestWriteMultipartBody_Success(t *testing.T) {
	t.Parallel()

	var buf strings.Builder

	w := multipart.NewWriter(&buf)
	if err := writeMultipartBody(w, []byte("DATA"), "doc.bin", []byte("FILECONTENT")); err != nil {
		t.Fatalf("writeMultipartBody: %v", err)
	}

	out := buf.String()
	for _, want := range []string{`name="data"`, `name="file"`, "doc.bin", "FILECONTENT"} {
		if !strings.Contains(out, want) {
			t.Errorf("multipart body missing %q", want)
		}
	}
}

// --- Tests for delegated user action signing (init / complete) ---
//
// The delegated flow splits signing so a challenge can be signed out-of-band (e.g. by an
// end user's device) instead of by a Signer held in this process: CreateUserActionChallenge
// returns the challenge, CompleteUserActionSigning exchanges the signed assertion for a
// user action token, and DoWithUserActionToken issues the request with that token.

func TestCreateUserActionChallenge(t *testing.T) {
	t.Parallel()

	var gotInit map[string]interface{}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/action/init" {
			t.Errorf("expected /auth/action/init, got %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotInit)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"challengeIdentifier":"ch-1","challenge":"c2ln"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)

	challenge, err := c.CreateUserActionChallenge(context.Background(), "POST", "/wallets", map[string]string{"network": "Eth"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if challenge.ChallengeIdentifier != "ch-1" {
		t.Errorf("expected challengeIdentifier ch-1, got %s", challenge.ChallengeIdentifier)
	}

	if challenge.Challenge != "c2ln" {
		t.Errorf("expected challenge c2ln, got %s", challenge.Challenge)
	}

	// The init request encodes the method, path and JSON-serialized body that will be signed.
	if gotInit["userActionHttpMethod"] != "POST" {
		t.Errorf("expected userActionHttpMethod POST, got %v", gotInit["userActionHttpMethod"])
	}

	if gotInit["userActionHttpPath"] != "/wallets" {
		t.Errorf("expected userActionHttpPath /wallets, got %v", gotInit["userActionHttpPath"])
	}

	if gotInit["userActionServerKind"] != "Api" {
		t.Errorf("expected userActionServerKind Api, got %v", gotInit["userActionServerKind"])
	}

	rawPayload, ok := gotInit["userActionPayload"].(string)
	if !ok {
		t.Fatalf("userActionPayload is not a string, got %T", gotInit["userActionPayload"])
	}

	var payload map[string]interface{}

	if err := json.Unmarshal([]byte(rawPayload), &payload); err != nil {
		t.Fatalf("userActionPayload is not JSON: %v", err)
	}

	if payload["network"] != "Eth" {
		t.Errorf("expected payload network Eth, got %v", payload["network"])
	}
}

func TestCreateUserActionChallenge_MarshalError(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("server should not be called when the body fails to marshal")
	})), nil)

	// A channel cannot be marshalled to JSON.
	_, err := c.CreateUserActionChallenge(context.Background(), "POST", "/wallets", map[string]interface{}{"bad": make(chan int)})
	if err == nil {
		t.Fatal("expected a marshal error for an unmarshalable body")
	}
}

func TestCreateUserActionChallenge_APIError(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`nope`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	if _, err := c.CreateUserActionChallenge(context.Background(), "POST", "/wallets", nil); err == nil {
		t.Fatal("expected an API error")
	}
}

func TestCompleteUserActionSigning(t *testing.T) {
	t.Parallel()

	var gotBody map[string]interface{}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/action" {
			t.Errorf("expected /auth/action, got %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"userAction":"ua-token"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	assertion := &signer.CredentialAssertion{
		Kind:                "Key",
		CredentialAssertion: signer.CredentialAssertionData{CredID: "cred-1", ClientData: "Y2Q", Signature: "c2ln"},
	}

	token, err := c.CompleteUserActionSigning(context.Background(), "ch-1", assertion)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "ua-token" {
		t.Errorf("expected token ua-token, got %s", token)
	}

	if gotBody["challengeIdentifier"] != "ch-1" {
		t.Errorf("expected challengeIdentifier ch-1, got %v", gotBody["challengeIdentifier"])
	}

	if _, ok := gotBody["firstFactor"]; !ok {
		t.Error("expected firstFactor in the /auth/action request body")
	}
}

func TestCompleteUserActionSigning_APIError(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	if _, err := c.CompleteUserActionSigning(context.Background(), "ch-1", &signer.CredentialAssertion{}); err == nil {
		t.Fatal("expected an API error")
	}
}

func TestDoWithUserActionToken_Success(t *testing.T) {
	t.Parallel()

	var (
		gotHeader string
		gotBody   map[string]interface{}
	)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-DFNS-USERACTION")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	// No signer configured — a delegated request carries a pre-obtained token instead.
	c := newTestClient(t, server, nil)

	var result struct {
		OK bool `json:"ok"`
	}

	err := c.DoWithUserActionToken(context.Background(), "POST", "/wallets", map[string]string{"network": "Eth"}, &result, "ua-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.OK {
		t.Fatal("expected ok=true")
	}

	if gotHeader != "ua-token" {
		t.Errorf("expected X-DFNS-USERACTION ua-token, got %s", gotHeader)
	}

	if gotBody["network"] != "Eth" {
		t.Errorf("expected body network Eth, got %v", gotBody["network"])
	}
}

func TestDoWithUserActionToken_EmptyTokenOmitsHeader(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Go canonicalizes the header name to "X-Dfns-Useraction".
		if _, ok := r.Header["X-Dfns-Useraction"]; ok {
			t.Error("expected no X-DFNS-USERACTION header for an empty token")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	if err := c.DoWithUserActionToken(context.Background(), "POST", "/x", nil, nil, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDoWithUserActionToken_MarshalError(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("server should not be called when the body fails to marshal")
	})), nil)

	err := c.DoWithUserActionToken(context.Background(), "POST", "/x", map[string]interface{}{"bad": make(chan int)}, nil, "ua")
	if err == nil {
		t.Fatal("expected a marshal error for an unmarshalable body")
	}
}

func TestDoWithUserActionToken_APIError(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`bad`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	err := c.DoWithUserActionToken(context.Background(), "POST", "/x", nil, nil, "ua")

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
}

// TestDelegatedFlow_EndToEnd exercises the whole init -> sign -> complete cycle without a
// local Signer: it obtains a challenge, simulates an out-of-band signature, exchanges it for
// a token, and confirms the final request carries that token.
func TestDelegatedFlow_EndToEnd(t *testing.T) {
	t.Parallel()

	var gotUserAction string

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/action/init", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signer.UserActionChallenge{ChallengeIdentifier: "ch-1", Challenge: "dGVzdA"})
	})
	mux.HandleFunc("/auth/action", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"userAction":"ua-token"}`))
	})
	mux.HandleFunc("/wallets", func(w http.ResponseWriter, r *http.Request) {
		gotUserAction = r.Header.Get("X-DFNS-USERACTION")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"wa-1"}`))
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := newTestClient(t, server, nil)

	body := map[string]string{"network": "Eth"}

	challenge, err := c.CreateUserActionChallenge(context.Background(), "POST", "/wallets", body)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Signing happens out-of-band; simulate the returned assertion.
	assertion := &signer.CredentialAssertion{Kind: "Key"}

	token, err := c.CompleteUserActionSigning(context.Background(), challenge.ChallengeIdentifier, assertion)
	if err != nil {
		t.Fatalf("complete failed: %v", err)
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := c.DoWithUserActionToken(context.Background(), "POST", "/wallets", body, &result, token); err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if result.ID != "wa-1" {
		t.Errorf("expected wallet id wa-1, got %s", result.ID)
	}

	if gotUserAction != "ua-token" {
		t.Errorf("expected X-DFNS-USERACTION ua-token on the final request, got %s", gotUserAction)
	}
}
