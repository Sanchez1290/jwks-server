package main

// This is a simple JWKS server that serves one valid and one expired RSA key.
import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// RSAKey represents an RSA key with its expiry and kid.
type RSAKey struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Expiry     time.Time
	Kid        string
}

// In-memory key store.
var keyStore = map[string]RSAKey{}

// Generate a new RSA key with a specified expiry offset (positive for future, negative for past).
func generateKey(expiryOffset time.Duration) RSAKey {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Generate a unique kid for the key.
	kid := uuid.New().String()

	return RSAKey{
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		Expiry:     time.Now().Add(expiryOffset),
		Kid:        kid,
	}
}

// Initialize 1 valid key and 1 expired key
func initKeys() {
	validKey := generateKey(1 * time.Hour)    // expires in future
	expiredKey := generateKey(-1 * time.Hour) // already expired

	keyStore[validKey.Kid] = validKey
	keyStore[expiredKey.Kid] = expiredKey
}

// JWKS handler
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	keys := []map[string]string{}

	for _, key := range keyStore {
		if key.Expiry.After(time.Now()) { // only unexpired keys
			n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())

			keys = append(keys, map[string]string{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": key.Kid,
				"n":   n,
				"e":   e,
			})
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": keys,
	})
}

// Auth handler
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if the request wants an expired token.
	expired := r.URL.Query().Has("expired")
	var chosenKey RSAKey
	found := false

	// Choose a key based on the expired query param.
	for _, key := range keyStore {
		if expired && key.Expiry.Before(time.Now()) {
			chosenKey = key
			found = true
			break
		}
		if !expired && key.Expiry.After(time.Now()) {
			chosenKey = key
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "No suitable key found", http.StatusInternalServerError)
		return
	}

	// Set token expiration based on expired query param
	expTime := time.Now().Add(1 * time.Hour)
	if expired {
		expTime = time.Now().Add(-1 * time.Hour)
	}

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = chosenKey.Kid
	token.Claims = jwt.MapClaims{
		"sub": "fakeuser",
		"iat": time.Now().Unix(),
		"exp": expTime.Unix(),
	}

	tokenString, err := token.SignedString(chosenKey.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
}

// Main function to start the server.
func main() {
	initKeys()

	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("JWKS server running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
