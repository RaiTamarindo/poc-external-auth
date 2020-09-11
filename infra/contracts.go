package infra

import "time"

// AuthProvider ...
type AuthProvider interface {
	Login(scope, username, password string) ([]byte, error)
	AddScopes(scopes []string) error
	GetUser(userID, userProvider string) (User, error)
	LinkUser(primaryUserID, primaryUserProvider, secondaryUserID, secondaryUserProvider string) error
}

// User ...
type User struct {
	ID       string `json:"user_id"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

// CacheProvider ...
type CacheProvider interface {
	Set(key string, value interface{}, expiration time.Duration)
	Get(key string) (result interface{}, found bool)
}
