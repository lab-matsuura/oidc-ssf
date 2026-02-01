// pkg/ssf/jwk_thumbprint_test.go
package ssf

import (
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestComputeJWKThumbprint(t *testing.T) {
	// RFC 7638 Appendix A の例に基づくテスト用公開鍵
	// n と e の値は実際の鍵から取得
	n := new(big.Int)
	n.SetString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", 10)
	e := 65537

	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	thumbprint, err := ComputeJWKThumbprint(pubKey)
	if err != nil {
		t.Fatalf("ComputeJWKThumbprint failed: %v", err)
	}

	// thumbprintは43文字程度のBase64URL文字列
	if len(thumbprint) < 40 || len(thumbprint) > 50 {
		t.Errorf("Unexpected thumbprint length: %d", len(thumbprint))
	}

	// 同じ鍵で再計算した場合、同じ結果になること
	thumbprint2, _ := ComputeJWKThumbprint(pubKey)
	if thumbprint != thumbprint2 {
		t.Errorf("Thumbprint not deterministic: %s != %s", thumbprint, thumbprint2)
	}

	t.Logf("Generated thumbprint: %s", thumbprint)
}

func TestComputeJWKThumbprint_NilKey(t *testing.T) {
	_, err := ComputeJWKThumbprint(nil)
	if err == nil {
		t.Error("Expected error for nil key, got nil")
	}
}
