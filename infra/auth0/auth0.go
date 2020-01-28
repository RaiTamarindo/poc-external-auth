package auth0

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/RaiTamarindo/poc-external-auth/infra"
)

// Provider ...
type Provider struct {
	audience                 string
	clientID                 string
	clientSecret             string
	resourceServerID         string
	authenticationAPIBaseURL string
	managementAPIBaseURL     string
	cache                    infra.CacheProvider
}

// NewProvider ...
func NewProvider(domain, audience, clientID, clientSecret, resourceServerID string, cache infra.CacheProvider) Provider {
	return Provider{
		audience:                 audience,
		clientID:                 clientID,
		clientSecret:             clientSecret,
		resourceServerID:         resourceServerID,
		authenticationAPIBaseURL: "https://" + domain + "/oauth/token",
		managementAPIBaseURL:     "https://" + domain + "/api/v2",
		cache:                    cache,
	}
}

// Login ...
func (a Provider) Login(scope, username, password string) ([]byte, error) {
	params := []string{
		"grant_type=password",
		fmt.Sprintf("scope=%s", scope),
		fmt.Sprintf("username=%s", username),
		fmt.Sprintf("password=%s", password),
		fmt.Sprintf("audience=%s", a.audience),
	}

	res, err := a.requestToken(params)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(res.Body)
}

type apiScope struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}

type apiServer struct {
	Scopes []apiScope `json:"scopes"`
}

// AddScopes ...
func (a Provider) AddScopes(scopes []string) error {
	jwt, err := a.getManagementToken()
	if err != nil {
		return err
	}

	u := a.authenticationAPIBaseURL + "/resource-servers/" + a.resourceServerID
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+jwt)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var api apiServer
	err = json.Unmarshal(raw, &api)
	if err != nil {
		return err
	}

	for _, s := range scopes {
		api.Scopes = append(api.Scopes, apiScope{
			Value:       s,
			Description: s + " scope",
		})
	}

	payload, err := json.Marshal(api)
	if err != nil {
		return err
	}
	req, err = http.NewRequest("PATCH", u, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+jwt)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return errors.New("error on updating resource server scopes")
	}

	return nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (a Provider) getManagementToken() (string, error) {
	var emptyToken string
	tokenCacheKey := "access_token"
	if t, found := a.cache.Get(tokenCacheKey); found {
		if token, ok := t.(string); ok {
			return token, nil
		}
	}

	params := []string{
		"grant_type=client_credentials",
		fmt.Sprintf("audience=%s", a.managementAPIBaseURL),
	}

	res, err := a.requestToken(params)
	if err != nil {
		return emptyToken, err
	}

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return emptyToken, err
	}

	var token tokenResponse
	err = json.Unmarshal(raw, &token)
	if err != nil {
		return emptyToken, err
	}

	expiration := time.Duration(token.ExpiresIn - time.Now().Unix())
	a.cache.Set(tokenCacheKey, token.AccessToken, expiration*time.Second)

	return token.AccessToken, nil
}

func (a Provider) requestToken(params []string) (*http.Response, error) {
	params = append(params,
		fmt.Sprintf("client_id=%s", a.clientID),
		fmt.Sprintf("client_secret=%s", a.clientSecret),
	)
	payload := strings.NewReader(strings.Join(params, "&"))
	req, err := http.NewRequest("POST", a.authenticationAPIBaseURL, payload)
	if err != nil {
		return nil, err
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	return http.DefaultClient.Do(req)
}
