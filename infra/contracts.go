package infra

import "io"

// AuthProvider ...
type AuthProvider interface {
	Login(username, password string) (io.ReadCloser, error)
}
