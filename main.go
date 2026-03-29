package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/golang-jwt/jwt/v5"
)

// -----------------------------
// DB SETUP
// -----------------------------
var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal(err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);
	`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}
}

// -----------------------------
// KEY GENERATION AND STORAGE
// -----------------------------
func generateKey(expiryOffset time.Duration) (*rsa.PrivateKey, int64) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	exp := time.Now().Add(expiryOffset).Unix()
	return key, exp
}

func saveKey(key *rsa.PrivateKey, exp int64) {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	_, err := db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", keyBytes, exp)
	if err != nil {
		log.Fatal(err)
	}
}

// -----------------------------
// SEED KEYS (one expired, one valid)
// -----------------------------
func initKeys() {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)

	if count == 0 {
		// valid key (1 hour in future)
		key1, exp1 := generateKey(1 * time.Hour)
		saveKey(key1, exp1)

		// expired key (1 hour in past)
		key2, exp2 := generateKey(-1 * time.Hour)
		saveKey(key2, exp2)
	}
}

// -----------------------------
// GET KEY FROM DB
// -----------------------------
func getKey(expired bool) (int, *rsa.PrivateKey) {
	now := time.Now().Unix()
	var row *sql.Row

	if expired {
		row = db.QueryRow("SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1", now)
	} else {
		row = db.QueryRow("SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", now)
	}

	var kid int
	var keyBytes []byte
	err := row.Scan(&kid, &keyBytes)
	if err != nil {
		log.Fatal(err)
	}

	privKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		log.Fatal(err)
	}

	return kid, privKey
}

// -----------------------------
// JWKS HELPER
// -----------------------------
func toBase64(n []byte) string {
	return base64.RawURLEncoding.EncodeToString(n)
}

func publicKeyToJWK(privKey *rsa.PrivateKey, kid int) map[string]string {
	pub := privKey.PublicKey
	n := toBase64(pub.N.Bytes())
	e := toBase64(big.NewInt(int64(pub.E)).Bytes())

	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": fmt.Sprintf("%d", kid),
		"n":   n,
		"e":   e,
	}
}

// -----------------------------
// JWKS HANDLER
// -----------------------------
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix())
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	keys := []map[string]string{}

	for rows.Next() {
		var kid int
		var keyBytes []byte
		rows.Scan(&kid, &keyBytes)

		privKey, _ := x509.ParsePKCS1PrivateKey(keyBytes)
		keys = append(keys, publicKeyToJWK(privKey, kid))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": keys,
	})
}

// -----------------------------
// AUTH HANDLER
// -----------------------------
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	expired := r.URL.Query().Get("expired") != ""
	kid, key := getKey(expired)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"username": "userABC",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = fmt.Sprintf("%d", kid)

	signed, err := token.SignedString(key)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(signed))
}

// -----------------------------
// MAIN
// -----------------------------
func main() {
	initDB()
	initKeys()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)

	fmt.Printf("JWKS server running on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
