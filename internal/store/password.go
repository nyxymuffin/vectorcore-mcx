package store

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Password verifiers for IdMS user authentication (TS 33.180 clause 5.1.2:
// the MC ID and credentials are verified by the IdM server; the credential
// mechanism itself is out of 3GPP scope, so a standard PBKDF2-SHA256 verifier
// is used). Format: pbkdf2$<iterations>$<salt-b64>$<hash-b64>.

const passwordIterations = 600_000

// HashPassword derives a stored verifier from a plaintext password.
func HashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		// rand.Read failing means the platform CSPRNG is broken; refuse to
		// produce a verifier rather than a weak one.
		panic(fmt.Sprintf("csprng unavailable: %v", err))
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, 32)
	if err != nil {
		panic(fmt.Sprintf("pbkdf2: %v", err))
	}
	return fmt.Sprintf("pbkdf2$%d$%s$%s", passwordIterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// VerifyPassword checks a plaintext password against a stored verifier in
// constant time. An empty verifier never matches.
func VerifyPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters < 1 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iters, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}
