package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/RaiTamarindo/poc-external-auth/infra"
	"github.com/RaiTamarindo/poc-external-auth/infra/auth0"
	"github.com/dgrijalva/jwt-go"
	"github.com/s12v/go-jwks"
)

type config struct {
	httpPort                 string
	httpEndpoint             string
	authProvider             string
	authProviderDomain       string
	authProviderClientID     string
	authProviderClientSecret string
	jwksURI                  string
}

func main() {

	config := config{
		httpPort:                 os.Getenv("HTTP_PORT"),
		httpEndpoint:             os.Getenv("HTTP_ENDPOINT"),
		authProvider:             os.Getenv("AUTH_PROVIDER"),
		authProviderDomain:       os.Getenv("AUTH_PROVIDER_DOMAIN"),
		authProviderClientID:     os.Getenv("AUTH_PROVIDER_CLIENT_ID"),
		authProviderClientSecret: os.Getenv("AUTH_PROVIDER_CLIENT_SECRET"),
		jwksURI:                  os.Getenv("JWKS_URI"),
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

	jwks, err := jwksSource.JSONWebKeySet()
	if err != nil {
		log.Fatal(err)
	}
	if len(jwks.Keys) < 1 {
		log.Fatalf("got any key from jwks source %s", config.jwksURI)
	}

	var authService infra.AuthProvider
	switch config.authProvider {
	case "auth0":
		authService = auth0.NewProvider(
			config.authProviderDomain,
			fmt.Sprintf("%s:%s", config.httpEndpoint, config.httpPort),
			config.authProviderClientID,
			config.authProviderClientSecret,
		)
	}

	authMiddleware := authenticationMiddleware{
		jwksClient: jwksClient,
		jwkID:      jwks.Keys[0].KeyID,
	}
	cors := corsMiddleware{}

	http.Handle("/validate", authMiddleware.validate(emptyHandler{}))
	http.Handle("/ping", cors.enable(authMiddleware.validate(pingHandler{})))
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) < 7 || strings.ToLower(authHeader[:7]) != "bearer " {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		credentials := strings.Split(authHeader[7:], ":")

		resBody, err := authService.Login(credentials[0], credentials[1])
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		written, err := io.Copy(w, resBody)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Printf("written %d bytes to response", written)
	})

	err = http.ListenAndServe(":"+config.httpPort, nil)
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
		bearerToken := authHeader[7:]

		jwk, err := m.jwksClient.GetEncryptionKey(m.jwkID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println(err.Error())
			return
		}

		_, err = jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			claims := token.Claims.(jwt.MapClaims)
			if _, ok := claims["sub"].(string); !ok {
				return nil, errors.New("missing sub claim")
			}

			return jwk.Key, nil
		})
		if err != nil {
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
