// pkg/ssf/jwk_thumbprint.go
package ssf

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// ComputeJWKThumbprint calculates RFC 7638 JWK Thumbprint for RSA public key.
// It creates a canonical JSON representation of the key's required members
// (e, kty, n in alphabetical order), hashes it with SHA-256, and returns
// the Base64URL-encoded result without padding.
func ComputeJWKThumbprint(pubKey *rsa.PublicKey) (string, error) {
	if pubKey == nil {
		return "", fmt.Errorf("public key is nil")
	}

	// Base64URL encode e and n (no padding)
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()
	nBytes := pubKey.N.Bytes()

	e := base64.RawURLEncoding.EncodeToString(eBytes)
	n := base64.RawURLEncoding.EncodeToString(nBytes)

	// Create canonical JSON (RFC 7638: members in lexicographic order)
	// For RSA keys: e, kty, n
	canonical := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, e, n)

	// SHA-256 hash
	hash := sha256.Sum256([]byte(canonical))

	// Base64URL encode (no padding)
	thumbprint := base64.RawURLEncoding.EncodeToString(hash[:])

	return thumbprint, nil
}
