package authenticators

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"github.com/arrikto/oidc-authservice/common"
	"github.com/pkg/errors"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type ServiceManagerAuthorizationData struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type AIPIPEAPIKeyAuthenticator struct {
	Header   string // header name where API key is presented
	AuthNURL string
}

// This tries to authenticate requests by asking the service manager to check the API key in a header.
func (s *AIPIPEAPIKeyAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := common.RequestLogger(r, "AIPIPE API key authenticator")

	if s.AuthNURL == "" {
		logger.Debug("No API key authn endpoint configured")
		return nil, false, nil
	}

	// Get auth from configured header. We leave this in the request format, most likely 'Basic base64(user-id:password)'.
	basic_auth_value := r.Header.Get(s.Header)
	if len(basic_auth_value) == 0 {
		logger.Debug("No basic auth found")
		return nil, false, nil
	}

	logger.Infof("Basic Auth Value: %s", basic_auth_value)

	// Check if the auth header value starts with 'Basic '
	if !strings.HasPrefix(basic_auth_value, "Basic ") {
		logger.Debug("Auth header provided is not Basic Auth")
		return nil, false, &common.AuthenticatorSpecificError{Err: errors.New("Invalid Auth Header")}
	}

	// Build a request to the service manager, copying the header value.
	req, err := http.NewRequest("GET", s.AuthNURL, nil)
	if err != nil {
		logger.Errorf("Service manager endpoint URL invalid: %v", err)
		return nil, false, &common.AuthenticatorSpecificError{Err: err}
	}

	req.Header.Add(s.Header, basic_auth_value)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("Calling service manager endpoint failed: %v", err)
		return nil, false, &common.AuthenticatorSpecificError{Err: err}
	}

	// Read the response
	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Reading response from service manager endpoint failed: %v", err)
		return nil, false, &common.AuthenticatorSpecificError{Err: err}
	}

	// Check the result. 401 is an authN failure, 200 is success and anything else is an error.
	if resp.StatusCode == 401 {
		// Authentication failed.
		// We have to return this as an 'authenticator specific error' so that the user isn't
		// redirected to the OIDC endpoint. That's a UI and not appropriate for an API-based
		// authentication method.
		logger.Debug("API key-based auth failed")
		return nil, false, &common.AuthenticatorSpecificError{Err: errors.New("API key invalid")}
	}

	if resp.StatusCode == 200 {
		var authZData ServiceManagerAuthorizationData
		err = json.Unmarshal(responseBody, &authZData)
		if err != nil {
			logger.Errorf("Unmarshalling response from service manager endpoint failed: %v", err)
			return nil, false, &common.AuthenticatorSpecificError{Err: err}
		}

		resp := &authenticator.Response{
			User: &user.DefaultInfo{
				UID:    authZData.Username,
				Groups: authZData.Groups,
				Extra:  map[string][]string{"auth-method": {"api-key"}},
			},
		}
		return resp, true, nil
	}

	logger.Errorf("Unexpected status code from service manager endpoint: %v %v", resp.StatusCode, resp.Status)
	return nil, false, &common.AuthenticatorSpecificError{Err: errors.New(resp.Status)}
}

func (s *AIPIPEAPIKeyAuthenticator) GetCacheKey(r *http.Request) string {
	return r.Header.Get(s.Header)
}
