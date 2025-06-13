package dfnsapiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"

	"github.com/dfns/dfns-sdk-go/internal/credentials"
)

const (
	UserActionHeader    = "x-dfns-useraction"
	authorizationHeader = "authorization"
	contentTypeHeader   = "Content-Type"
)

type AuthTransportConfig struct {
	OrgID     *string
	AuthToken *string
	BaseURL   string
	Signer    credentials.ICredentialSigner
}

type AuthTransport struct {
	*AuthTransportConfig
}

func NewAuthTransport(config *AuthTransportConfig) *AuthTransport {
	return &AuthTransport{config}
}

func (auth *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	err := auth.setHeaders(req)
	if err != nil {
		return nil, err
	}

	performUserAction, err := shouldPerformUserAction(req)
	if err != nil {
		return nil, err
	}

	req.Header.Del(UserActionHeader)

	if performUserAction {
		if err := auth.performUserActionRequest(req); err != nil {
			return nil, err
		}
	}

	return executeRequest(req)
}

func shouldPerformUserAction(req *http.Request) (bool, error) {
	if ok := slices.Contains([]string{"POST", "PUT", "DELETE"}, req.Method); !ok {
		return false, nil
	}

	authHeaderStr := req.Header.Get(UserActionHeader)
	if authHeaderStr == "" {
		return true, nil
	}

	authHeader, err := strconv.ParseBool(authHeaderStr)
	if err != nil {
		return false, fmt.Errorf("error parsing header value as boolean: %w", err)
	}

	return authHeader, nil
}

// PerformSimpleRequest performs a simple HTTP request.
func (auth *AuthTransport) performSimpleRequest(req *http.Request) (*http.Response, error) {
	err := auth.setHeaders(req)
	if err != nil {
		return nil, err
	}

	return executeRequest(req)
}

// PerformUserActionRequest performs a user action HTTP request.
func (auth *AuthTransport) performUserActionRequest(req *http.Request) error {
	err := auth.setHeaders(req)
	if err != nil {
		return err
	}

	return auth.executeUserActionRequest(req)
}

// setHeaders sets the request headers.
func (auth *AuthTransport) setHeaders(req *http.Request) error {
	if auth.AuthToken != nil {
		// Only validate organization if OrgID is provided
		if auth.OrgID != nil {
			err := AssertAuthTokenIsSameOrg(*auth.AuthToken, *auth.OrgID)
			if err != nil {
				return err
			}
		}

		req.Header.Set(authorizationHeader, "Bearer "+*auth.AuthToken)
	}

	req.Header.Set(contentTypeHeader, "application/json")

	return nil
}

func executeRequest(req *http.Request) (*http.Response, error) {
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing request: %w", err)
	}

	// Fill Request otherwise it's nil
	response.Request = req

	if err := handleResponseError(response); err != nil {
		return nil, err
	}

	return response, nil
}

// handleResponseError handles errors in the HTTP response.
func handleResponseError(response *http.Response) error {
	if response.StatusCode < 400 && response.StatusCode != PolicyPendingErrorCode {
		return nil // No error, return nil
	}

	respBody, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	defer response.Body.Close()

	var body map[string]interface{}
	if err := json.Unmarshal(respBody, &body); err != nil {
		return fmt.Errorf("failed to parse response body: %w", err)
	}

	if response.StatusCode == PolicyPendingErrorCode {
		return NewPolicyPendingError(body)
	}

	var message string

	if errorObj, ok := body["error"].(map[string]interface{}); ok {
		if errMsg, ok := errorObj["message"].(string); ok {
			message = errMsg
		}
	} else if errMsg, ok := body["message"].(string); ok {
		message = errMsg
	} else {
		message = "Unknown error"
	}

	return NewDfnsError(response.StatusCode, message, map[string]interface{}{
		"URL":     response.Request.URL.String(),
		"Headers": response.Request.Header,
		"Body":    body,
	})
}

// executeUserActionRequest executes a user action HTTP request.
func (auth *AuthTransport) executeUserActionRequest(req *http.Request) error {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("couldn't read user action request body: %w", err)
	}
	defer req.Body.Close()

	req.Body = io.NopCloser(bytes.NewReader(body))

	createUserActionResp, err := auth.createUserActionChallenge(req.Context(),
		string(body), req.Method, req.URL.Path)
	if err != nil {
		return err
	}

	assertion, err := auth.Signer.Sign(req.Context(),
		&credentials.UserActionChallenge{
			Challenge:        createUserActionResp.Challenge,
			AllowCredentials: createUserActionResp.AllowCredentials,
		})
	if err != nil {
		return fmt.Errorf("error signing the user challenge: %w", err)
	}

	userAction, err := auth.signUserActionChallenge(req.Context(),
		createUserActionResp.ChallengeIdentifier, assertion)
	if err != nil {
		return err
	}

	req.Header.Set("x-dfns-useraction", userAction)

	return nil
}

// createUserActionChallengeRequest represents the request payload for creating
// a user action challenge.
type createUserActionChallengeRequest struct {
	UserActionPayload    string `json:"userActionPayload"`
	UserActionHTTPMethod string `json:"userActionHttpMethod"`
	UserActionHTTPPath   string `json:"userActionHttpPath"`
	UserActionServerKind string `json:"userActionServerKind"`
}

// createUserActionChallengeResponse represents the response format for a user
// action challenge creation request.
type createUserActionChallengeResponse struct {
	Challenge           string                        `json:"challenge"`
	ChallengeIdentifier string                        `json:"challengeIdentifier"`
	AllowCredentials    *credentials.AllowCredentials `json:"allowCredentials"`
}

// createUserActionChallenge creates the user action challenge.
func (auth *AuthTransport) createUserActionChallenge(
	ctx context.Context, body, method, path string,
) (*createUserActionChallengeResponse, error) {
	payload := createUserActionChallengeRequest{
		UserActionPayload:    body,
		UserActionHTTPMethod: method,
		UserActionHTTPPath:   path,
		UserActionServerKind: "Api",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("Error marshaling JSON: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		auth.BaseURL+"/auth/action/init", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("Error creating request: %w", err)
	}

	response, err := auth.performSimpleRequest(req)
	if err != nil {
		return nil, err
	}

	respBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("couldn't read body: %w", err)
	}
	defer response.Body.Close()

	var challengeResponse createUserActionChallengeResponse

	err = json.Unmarshal(respBody, &challengeResponse)
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal challenge response: %w", err)
	}

	return &createUserActionChallengeResponse{
		Challenge:           challengeResponse.Challenge,
		ChallengeIdentifier: challengeResponse.ChallengeIdentifier,
		AllowCredentials:    challengeResponse.AllowCredentials,
	}, nil
}

// signUserActionChallengeRequest represents the request payload for signing a user action challenge.
type signUserActionChallengeRequest struct {
	ChallengeIdentifier string                    `json:"challengeIdentifier"`
	FirstFactor         *credentials.KeyAssertion `json:"firstFactor"`
}

// signUserActionResponse represents the response format for signing a user
// action challenge.
type signUserActionResponse struct {
	UserAction string `json:"userAction"`
}

// signUserActionChallenge signs the user action challenge.
func (auth *AuthTransport) signUserActionChallenge(
	ctx context.Context,
	challengeIdentifier string,
	firstFactor *credentials.KeyAssertion,
) (string, error) {
	payload := signUserActionChallengeRequest{
		ChallengeIdentifier: challengeIdentifier,
		FirstFactor:         firstFactor,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("Error marshaling JSON: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		auth.BaseURL+"/auth/action", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("Error creating request: %w", err)
	}

	response, err := auth.performSimpleRequest(req)
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("couldn't read body: %w", err)
	}
	defer response.Body.Close()

	var signResponse signUserActionResponse

	err = json.Unmarshal(body, &signResponse)
	if err != nil {
		return "", fmt.Errorf("couldn't unmarshaling user action response: %w", err)
	}

	return signResponse.UserAction, nil
}
