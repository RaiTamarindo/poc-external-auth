package infra

// AuthProvider ...
type AuthProvider interface {
	Login(scope, username, password string) ([]byte, error)
}
