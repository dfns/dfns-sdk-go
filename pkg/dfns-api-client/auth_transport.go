package dfns_api_client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"

	"github.com/dfns/dfns-sdk-go/pkg/credentials"
)

const (
	UserActionHeader    = "x-dfns-useraction"
	appIDHeader         = "x-dfns-appid"
	nonceHeader         = "x-dfns-nonce"
	authorizationHeader = "authorization"
	contentTypeHeader   = "Content-Type"
)

type authTransport struct {
	*DfnsApiOptions
}

func (auth *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	auth.setHeaders(req)

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
func (auth *authTransport) performSimpleRequest(req *http.Request) (*http.Response, error) {
	auth.setHeaders(req)

	return executeRequest(req)
}

// PerformUserActionRequest performs a user action HTTP request.
func (auth *authTransport) performUserActionRequest(req *http.Request) error {
	auth.setHeaders(req)

	return auth.executeUserActionRequest(req)
}

// setHeaders sets the request headers.
func (auth *authTransport) setHeaders(req *http.Request) {
	req.Header.Set(appIDHeader, auth.AppId)
	req.Header.Set(nonceHeader, generateNonce())

	if auth.AuthToken != nil {
		req.Header.Set(authorizationHeader, "Bearer "+*auth.AuthToken)
	}

	req.Header.Set(contentTypeHeader, "application/json")
}

func executeRequest(req *http.Request) (*http.Response, error) {
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
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
		return fmt.Errorf("failed to read response body: %v", err)
	}
	defer response.Body.Close()

	var body map[string]interface{}
	if err := json.Unmarshal(respBody, &body); err != nil {
		return fmt.Errorf("failed to parse response body: %v", err)
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
func (auth *authTransport) executeUserActionRequest(req *http.Request) error {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	defer req.Body.Close()

	req.Body = io.NopCloser(bytes.NewReader(body))

	createUserActionResp, err := auth.createUserActionChallenge(string(body), req.Method, req.URL.Path)
	if err != nil {
		return err
	}

	assertion, err := auth.Signer.Sign(createUserActionResp.Challenge, createUserActionResp.AllowCredentials)
	if err != nil {
		return err
	}

	userAction, err := auth.signUserActionChallenge(createUserActionResp.ChallengeIdentifier, assertion)
	if err != nil {
		return err
	}

	req.Header.Set("x-dfns-useraction", userAction)

	return nil
}

// createUserActionChallengeRequest represents the request payload for creating a user action challenge.
type createUserActionChallengeRequest struct {
	UserActionPayload    string `json:"userActionPayload"`
	UserActionHttpMethod string `json:"userActionHttpMethod"`
	UserActionHttpPath   string `json:"userActionHttpPath"`
	UserActionServerKind string `json:"userActionServerKind"`
}

// createUserActionChallengeResponse represents the response format for a user action challenge creation request.
type createUserActionChallengeResponse struct {
	Challenge           string                        `json:"challenge"`
	ChallengeIdentifier string                        `json:"challengeIdentifier"`
	AllowCredentials    *credentials.AllowCredentials `json:"allowCredentials"`
}

// createUserActionChallenge creates the user action challenge.
func (auth *authTransport) createUserActionChallenge(body, method, path string) (*createUserActionChallengeResponse, error) {
	payload := createUserActionChallengeRequest{
		UserActionPayload:    body,
		UserActionHttpMethod: method,
		UserActionHttpPath:   path,
		UserActionServerKind: "Api",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("Error marshaling JSON: %v", err)
	}

	req, err := http.NewRequest("POST", auth.BaseUrl+"/auth/action/init", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("Error creating request: %v", err)
	}

	response, err := auth.performSimpleRequest(req)
	if err != nil {
		return nil, err
	}

	respBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("couldn't read body: %v", err)
	}
	defer response.Body.Close()

	var challengeResponse createUserActionChallengeResponse
	err = json.Unmarshal(respBody, &challengeResponse)
	if err != nil {
		return nil, err
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

// signUserActionResponse represents the response format for signing a user action challenge.
type signUserActionResponse struct {
	UserAction string `json:"userAction"`
}

// signUserActionChallenge signs the user action challenge.
func (auth *authTransport) signUserActionChallenge(challengeIdentifier string, firstFactor *credentials.KeyAssertion) (string, error) {
	payload := signUserActionChallengeRequest{
		ChallengeIdentifier: challengeIdentifier,
		FirstFactor:         firstFactor,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("Error marshaling JSON: %v", err)
	}

	req, err := http.NewRequest("POST", auth.BaseUrl+"/auth/action", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("Error creating request: %v", err)
	}

	response, err := auth.performSimpleRequest(req)
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("couldn't read body: %v", err)
	}
	defer response.Body.Close()

	var signResponse signUserActionResponse
	err = json.Unmarshal(body, &signResponse)
	if err != nil {
		return "", err
	}

	return signResponse.UserAction, nil
}
