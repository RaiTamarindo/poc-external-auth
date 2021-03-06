package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/s12v/go-jwks"

	"github.com/RaiTamarindo/poc-external-auth/infra"
	"github.com/RaiTamarindo/poc-external-auth/infra/auth0"
	"github.com/RaiTamarindo/poc-external-auth/infra/awscognito"
	"github.com/RaiTamarindo/poc-external-auth/infra/memorycache"
)

type config struct {
	httpPort                 string
	httpEndpoint             string
	authProvider             string
	authProviderDomain       string
	authProviderClientID     string
	authProviderClientSecret string
	authProviderAPIServerID  string
	jwksURI                  string
	awsKeyID                 string
	awsSecretKey             string
}

func main() {

	config := config{
		httpPort:                 os.Getenv("HTTP_PORT"),
		httpEndpoint:             os.Getenv("HTTP_ENDPOINT"),
		authProvider:             os.Getenv("AUTH_PROVIDER"),
		authProviderDomain:       os.Getenv("AUTH_PROVIDER_DOMAIN"),
		authProviderClientID:     os.Getenv("AUTH_PROVIDER_CLIENT_ID"),
		authProviderClientSecret: os.Getenv("AUTH_PROVIDER_CLIENT_SECRET"),
		authProviderAPIServerID:  os.Getenv("AUTH_PROVIDER_API_SERVER_ID"),
		jwksURI:                  os.Getenv("JWKS_URI"),
		awsKeyID:                 os.Getenv("AWS_KEY_ID"),
		awsSecretKey:             os.Getenv("AWS_SECRET_KEY"),
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
		os.Exit(1)
	}
	if len(jwks.Keys) < 1 {
		log.Fatalf("got any key from jwks source %s", config.jwksURI)
		os.Exit(1)
	}

	var authService infra.AuthProvider
	switch config.authProvider {
	case "auth0":
		cache := memorycache.NewClient(5*time.Minute, 10*time.Minute)
		authService = auth0.NewProvider(
			config.authProviderDomain,
			fmt.Sprintf("%s:%s", config.httpEndpoint, config.httpPort),
			config.authProviderClientID,
			config.authProviderClientSecret,
			config.authProviderAPIServerID,
			cache,
		)
	case "awscognito":
		authService = awscognito.NewProvider(
			config.jwksURI,
			config.awsKeyID,
			config.awsSecretKey,
			config.authProviderClientID,
		)
	}

	authMiddleware := authenticationMiddleware{
		jwksClient: jwksClient,
	}
	cors := corsMiddleware{}

	http.Handle("/validate", authMiddleware.validate(emptyHandler{}))
	http.Handle("/ping", cors.enable(authMiddleware.validate(pingHandler{})))
	http.Handle("/link-user", cors.enable(authMiddleware.validate(linkUserHandler{
		authService: authService,
		IDByEmail: map[string]string{
			"raybatera_@outlook.com": "my-internal-identifier-3",
		},
	})))
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) < 7 || strings.ToLower(authHeader[:7]) != "bearer " {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		credentials := strings.Split(authHeader[7:], ":")
		if len(credentials) < 3 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		resBody, err := authService.Login(credentials[0], credentials[1], credentials[2])
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		fmt.Fprint(w, string(resBody))
	})
	http.HandleFunc("/scopes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		raw, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var scopes []string
		err = json.Unmarshal(raw, &scopes)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = authService.AddScopes(scopes)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})

	err = http.ListenAndServe(":"+config.httpPort, nil)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}

type pingHandler struct{}

func (h pingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `{"timestamp":%d,"message":"pong"}`, time.Now().Unix())
}

type linkUserHandler struct {
	authService infra.AuthProvider
	IDByEmail   map[string]string
}

func (h linkUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sub := r.URL.Query().Get("sub")
	subParts := strings.Split(sub, "|")
	if len(subParts) < 2 {
		log.Println("invalid sub claim")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	secondaryUserProvider := subParts[0]
	secondaryUserID := subParts[1]

	secondaryUser, err := h.authService.GetUser(secondaryUserID, secondaryUserProvider)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusNotFound)
		return
	}

	primaryUserID := h.IDByEmail[secondaryUser.Email]

	err = h.authService.LinkUser(primaryUserID, "auth0", secondaryUserID, secondaryUserProvider)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

type emptyHandler struct{}

func (h emptyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

type authenticationMiddleware struct {
	jwksClient jwks.JWKSClient
}

func (m authenticationMiddleware) validate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		bearerToken := authHeader[7:]

		_, err := jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			claims := token.Claims.(jwt.MapClaims)
			if _, ok := claims["sub"].(string); !ok {
				return nil, errors.New("missing sub claim")
			}

			k, ok := token.Header["kid"]
			if !ok {
				return nil, errors.New("missing kid header")
			}
			keyID, ok := k.(string)
			if !ok {
				return nil, errors.New("can't parse kid header")
			}

			jwk, err := m.jwksClient.GetEncryptionKey(keyID)
			if err != nil {
				return nil, err
			}

			return jwk.Key, nil
		})
		if err != nil {
			log.Println(err.Error())
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
		w.Header().Add("Access-Control-Allow-Methods", "*")
		w.Header().Add("Access-Control-Allow-Headers", "*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
