# JWKS Server (Go)

This project is a simple **JWKS (JSON Web Key Set) server** written in Go.
It generates **one valid RSA key** and **one expired RSA key**, then serves the valid key through a JWKS endpoint. It also provides an authentication endpoint that generates JWT tokens signed with the RSA keys.

---

## Live Deployment (Render)

Base URL:

```
https://jwks-server-pg3j.onrender.com 
```

---

## Endpoints

### JWKS Endpoint (GET)

Returns the active (non-expired) public RSA key in JWKS format.

```
GET /.well-known/jwks.json
```

Example:

```bash
curl https://jwks-server-pg3j.onrender.com/.well-known/jwks.json
```

---

### Auth Endpoint (POST)

Returns a JWT signed with a valid RSA private key.

```
POST /auth
```

Example:

```bash
curl -X POST https://jwks-server-pg3j.onrender.com/auth
```

---

### Expired Token Endpoint (POST)

Returns a JWT signed with the expired RSA key.

```
POST /auth?expired=true
```

Example:

```bash
curl -X POST "https://jwks-server-pg3j.onrender.com/auth?expired=true"
```

---

## 🛠 Running Locally

### 1. Clone the repo

```bash
git clone https://github.com/Sanchez1290/jwks-server.git
cd jwks-server
```

### 2. Install dependencies

```bash
go mod tidy
```

### 3. Run the server

```bash
go run main.go
```

Server will run at:

```
http://localhost:8080
```

---

## 🧪 Testing

### JWKS Test

```bash
curl http://localhost:8080/.well-known/jwks.json
```

### Auth Token Test

```bash
curl -X POST http://localhost:8080/auth
```

### Expired Token Test

```bash
curl -X POST "http://localhost:8080/auth?expired=true"
```

---

## Assignment Deliverables

This repository includes:

* Source code for JWKS server
* Live Render deployment link
* Screenshots of:

  * Test client calling JWKS/auth endpoints
  * Test suite output (if present) and coverage %

---

## Dependencies

* `github.com/golang-jwt/jwt/v5`
* `github.com/google/uuid`
