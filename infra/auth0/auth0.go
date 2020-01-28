package auth0

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// Provider ...
type Provider struct {
	domain       string
	audience     string
	clientID     string
	clientSecret string
}

// NewProvider ...
func NewProvider(domain, audience, clientID, clientSecret string) Provider {
	return Provider{
		domain:       domain,
		audience:     audience,
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Login ...
func (a Provider) Login(scope, username, password string) ([]byte, error) {
	url := fmt.Sprintf("https://%s/oauth/token", a.domain)
	params := []string{
		"grant_type=password",
		fmt.Sprintf("scope=%s", scope),
		fmt.Sprintf("username=%s", username),
		fmt.Sprintf("password=%s", password),
		fmt.Sprintf("audience=%s", a.audience),
		fmt.Sprintf("client_id=%s", a.clientID),
		fmt.Sprintf("client_secret=%s", a.clientSecret),
	}
	payload := strings.NewReader(strings.Join(params, "&"))
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return nil, err
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(res.Body)
}
