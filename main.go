package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/s12v/go-jwks"
	"github.com/square/go-jose"
)

type config struct {
	httpPort string
	jwksURI  string
	jwkID    string
}

func main() {

	config := config{
		httpPort: os.Getenv("HTTP_PORT"),
		jwksURI:  os.Getenv("JWKS_URI"),
		jwkID:    os.Getenv("JWK_ID"),
	}

	serve(config)
}

func serve(config config) {
	jwksSource := jwks.NewWebSource(config.jwksURI)
	jwksClient := jwks.NewDefaultClient(
		jwksSource,
		time.Hour,    // Refresh keys every 1 hour
		12*time.Hour, // Expire keys after 12 hours
	)

	auth := authenticationMiddleware{
		jwksClient: jwksClient,
		jwkID:      config.jwkID,
	}

	http.HandleFunc("/validate", auth.validate)

	err := http.ListenAndServe(":"+config.httpPort, nil)
	if err != nil {
		log.Fatal(err)
	}

}

type authenticationMiddleware struct {
	jwksClient jwks.JWKSClient
	jwkID      string
}

func (m authenticationMiddleware) validate(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jws, err := jose.ParseSigned(authHeader[7:])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println(err.Error())
		return
	}
	jwk, err := m.jwksClient.GetEncryptionKey(m.jwkID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println(err.Error())
		return
	}

	if _, err := jws.Verify(jwk.Key); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
		return
	}
}
