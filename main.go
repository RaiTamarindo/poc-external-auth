package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/s12v/go-jwks"
	"github.com/square/go-jose"
)

type config struct {
	httpPort                 string
	httpEndpoint             string
	jwksURI                  string
	jwkID                    string
	authProviderDomain       string
	authProviderClientID     string
	authProviderClientSecret string
}

func main() {

	config := config{
		httpPort:                 os.Getenv("HTTP_PORT"),
		httpEndpoint:             os.Getenv("HTTP_ENDPOINT"),
		jwksURI:                  os.Getenv("JWKS_URI"),
		jwkID:                    os.Getenv("JWK_ID"),
		authProviderDomain:       os.Getenv("AUTH_PROVIDER_DOMAIN"),
		authProviderClientID:     os.Getenv("AUTH_PROVIDER_CLIENT_ID"),
		authProviderClientSecret: os.Getenv("AUTH_PROVIDER_CLIENT_SECRET"),
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
	cors := corsMiddleware{}

	http.Handle("/validate", auth.validate(emptyHandler{}))
	http.Handle("/ping", cors.enable(auth.validate(pingHandler{})))
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) < 7 || strings.ToLower(authHeader[:7]) != "bearer " {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		credentials := strings.Split(authHeader[7:], ":")

		url := fmt.Sprintf("https://%s/oauth/token", config.authProviderDomain)
		params := []string{
			"grant_type=password",
			"scope=read%3Asample",
			fmt.Sprintf("username=%s", credentials[0]),
			fmt.Sprintf("password=%s", credentials[1]),
			fmt.Sprintf("audience=%s:%s", config.httpEndpoint, config.httpPort),
			fmt.Sprintf("client_id=%s", config.authProviderClientID),
			fmt.Sprintf("client_secret=%s", config.authProviderClientSecret),
		}
		payload := strings.NewReader(strings.Join(params, "&"))
		req, err := http.NewRequest("POST", url, payload)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		req.Header.Add("content-type", "application/x-www-form-urlencoded")

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		written, err := io.Copy(w, res.Body)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Printf("written %d bytes to response", written)
	})

	err := http.ListenAndServe(":"+config.httpPort, nil)
	if err != nil {
		log.Fatal(err)
	}

}

type pingHandler struct{}

func (h pingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `{"timestamp":%d,"message":"pong"}`, time.Now().Unix())
}

type emptyHandler struct{}

func (h emptyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

type authenticationMiddleware struct {
	jwksClient jwks.JWKSClient
	jwkID      string
}

func (m authenticationMiddleware) validate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		next.ServeHTTP(w, r)
	})
}

type corsMiddleware struct{}

func (m corsMiddleware) enable(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "DELETE, POST, GET, OPTIONS")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
