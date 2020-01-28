package infra

import "time"

// AuthProvider ...
type AuthProvider interface {
	Login(scope, username, password string) ([]byte, error)
	AddScopes(scopes []string) error
}

// CacheProvider ...
type CacheProvider interface {
	Set(key string, value interface{}, expiration time.Duration)
	Get(key string) (result interface{}, found bool)
}
