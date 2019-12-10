package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type AzurePublicKeys struct {
	Keys []AzurePublicKey `json:"keys"`
}

type AzurePublicKey struct {
	Kid       string   `json:"kid"`
	X5C       []string `json:"x5c"`
	PublicKey *rsa.PublicKey
}

var publicKeys map[string]*rsa.PublicKey
var apiAudience string
var publicKeysEndpoint string

func main() {
	go func() {
		for true {
			loadPublicKeys()
			time.Sleep(10 * time.Minute)
		}
	}()

	apiAudience = os.Getenv("API_RESOURCE_ID")

	publicKeysEndpoint = os.Getenv("PUBLIC_KEYS_ENDPOINT")
	if publicKeysEndpoint == "" {
		publicKeysEndpoint = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	router := mux.NewRouter().StrictSlash(true)
	router.PathPrefix("/").HandlerFunc(authorizeRequest)
	log.Printf("listening on port %s for audience %s. Using public keys from %s", port, apiAudience, publicKeysEndpoint)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), router))
}

func authorizeRequest(w http.ResponseWriter, r *http.Request) {
	// 401 Unauthorized - not authenticated
	// 403 Forbidden - not authorized
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		errMsg := "Unauthorized - missing access token in Authorization header"
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, errMsg)
		log.Print(errMsg)
	} else if !strings.Contains(authorization, "Bearer ") && !strings.Contains(authorization, "bearer ") {
		errMsg := fmt.Sprintf("Unauthorized - Authorization should be prefixed with \"Bearer\". Current value %s", authorization)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, errMsg)
		log.Print(errMsg)
	} else {
		token := authorization[7:len(authorization)]
		err := validateToken(token)
		if err != nil {
			errMsg := fmt.Sprintf("Forbidden - %v", err)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, errMsg)
			log.Print(errMsg)
		} else {
			w.WriteHeader(http.StatusNoContent)
			log.Print("authorized request (token)")
		}
	}
}

func validateToken(token string) error {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		publicKey := getPublicKey(fmt.Sprintf("%v", token.Header["kid"]))
		return publicKey, nil
	})
	if err != nil {
		return err
	}
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		audience := fmt.Sprintf("%v", claims["aud"])
		if audience != apiAudience {
			return fmt.Errorf("expected audience %s, was %s", apiAudience, audience)
		}
	} else {
		return fmt.Errorf("invalid token")
	}

	return nil
}

func loadPublicKeys() error {
	kidToKey := map[string]*rsa.PublicKey{}
	keys := AzurePublicKeys{}
	r, err := http.Get(publicKeysEndpoint)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	err = json.NewDecoder(r.Body).Decode(&keys)
	if err != nil {
		return err
	}
	for _, key := range keys.Keys {
		kidToKey[key.Kid] = createPublicKey(key.X5C[0])
	}
	publicKeys = kidToKey
	log.Printf("public keys loaded")
	return nil
}

func getPublicKey(kid string) *rsa.PublicKey {
	return publicKeys[kid]
}

func createPublicKey(publicKey string) *rsa.PublicKey {
	pk := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", publicKey)
	pkByte := []byte(pk)
	block, _ := pem.Decode(pkByte)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	return cert.PublicKey.(*rsa.PublicKey)
}
