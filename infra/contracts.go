package infra

// AuthProvider ...
type AuthProvider interface {
	Login(username, password string) ([]byte, error)
}
