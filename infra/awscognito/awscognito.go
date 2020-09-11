package awscognito

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/RaiTamarindo/poc-external-auth/infra"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

// Provider ...
type Provider struct {
	cognitoClient *cognitoidentityprovider.CognitoIdentityProvider
	userPoolID    string
	clientID      string
}

// NewProvider ...
func NewProvider(jwksURI, awsKeyID, awsSecretKey, clientID string) Provider {
	uriParts := strings.Split(jwksURI[8:], "/")
	domainParts := strings.Split(uriParts[0], ".")
	return Provider{
		cognitoClient: cognitoidentityprovider.New(session.New(&aws.Config{
			Region:      aws.String(domainParts[1]),
			Credentials: credentials.NewStaticCredentials(awsKeyID, awsSecretKey, ""),
		})),
		userPoolID: uriParts[1],
		clientID:   clientID,
	}
}

// Login ...
func (p Provider) Login(_, username, password string) ([]byte, error) {
	out, err := p.cognitoClient.AdminInitiateAuth(&cognitoidentityprovider.AdminInitiateAuthInput{
		AuthFlow:   aws.String("ADMIN_USER_PASSWORD_AUTH"),
		ClientId:   aws.String(p.clientID),
		UserPoolId: aws.String(p.userPoolID),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String(username),
			"PASSWORD": aws.String(password),
		},
	})
	if err != nil {
		return nil, err
	}

	return json.Marshal(out.AuthenticationResult)
}

// AddScopes ...
func (p Provider) AddScopes(scopes []string) error {
	return errors.New("not implemented")
}

// GetUser ...
func (p Provider) GetUser(userID, userProvider string) (infra.User, error) {
	return infra.User{}, errors.New("unimplemented method")
}

// LinkUser ...
func (p Provider) LinkUser(primaryUserID, primaryUserProvider, secondaryUserID, secondaryUserProvider string) error {
	return errors.New("unimplemented method")
}
