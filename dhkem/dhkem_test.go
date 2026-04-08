package dhkem_test

import (
	"testing"

	"github.com/jwx-go/x448/v4/dhkem"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	sk, err := dhkem.GenerateKey()
	require.NoError(t, err)
	require.NotNil(t, sk)
	require.NotNil(t, sk.PublicKey())
	require.Len(t, sk.Bytes(), dhkem.Nsk)
	require.Len(t, sk.PublicKey().Bytes(), dhkem.Npk)
}

func TestKeySerialization(t *testing.T) {
	sk, err := dhkem.GenerateKey()
	require.NoError(t, err)

	// Private key roundtrip
	sk2, err := dhkem.NewPrivateKey(sk.Bytes())
	require.NoError(t, err)
	require.Equal(t, sk.Bytes(), sk2.Bytes())
	require.Equal(t, sk.PublicKey().Bytes(), sk2.PublicKey().Bytes())

	// Public key roundtrip
	pk, err := dhkem.NewPublicKey(sk.PublicKey().Bytes())
	require.NoError(t, err)
	require.Equal(t, sk.PublicKey().Bytes(), pk.Bytes())
}

func TestKeySerializationErrors(t *testing.T) {
	_, err := dhkem.NewPublicKey(make([]byte, 10))
	require.Error(t, err)

	_, err = dhkem.NewPrivateKey(make([]byte, 10))
	require.Error(t, err)
}

func TestEncapDecap(t *testing.T) {
	// Generate recipient key pair
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	// Encap: sender generates shared secret + encapsulated key
	sharedSecret1, enc, err := dhkem.Encap(skR.PublicKey())
	require.NoError(t, err)
	require.Len(t, sharedSecret1, dhkem.Nsecret)
	require.Len(t, enc, dhkem.Nenc)

	// Decap: recipient recovers the same shared secret
	sharedSecret2, err := dhkem.Decap(enc, skR)
	require.NoError(t, err)
	require.Equal(t, sharedSecret1, sharedSecret2)
}

func TestEncapDecapMultiple(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	// Multiple encaps should produce different enc and shared secrets
	ss1, enc1, err := dhkem.Encap(skR.PublicKey())
	require.NoError(t, err)

	ss2, enc2, err := dhkem.Encap(skR.PublicKey())
	require.NoError(t, err)

	require.NotEqual(t, enc1, enc2, "encapsulated keys should differ")
	require.NotEqual(t, ss1, ss2, "shared secrets should differ")

	// Both should decap correctly
	dec1, err := dhkem.Decap(enc1, skR)
	require.NoError(t, err)
	require.Equal(t, ss1, dec1)

	dec2, err := dhkem.Decap(enc2, skR)
	require.NoError(t, err)
	require.Equal(t, ss2, dec2)
}

func TestDecapWrongKey(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	skWrong, err := dhkem.GenerateKey()
	require.NoError(t, err)

	ss1, enc, err := dhkem.Encap(skR.PublicKey())
	require.NoError(t, err)

	// Decap with wrong key should produce different shared secret
	ss2, err := dhkem.Decap(enc, skWrong)
	require.NoError(t, err) // DH itself succeeds (not a low-order point)
	require.NotEqual(t, ss1, ss2, "shared secret with wrong key should differ")
}

func TestDecapInvalidEnc(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	// Too short
	_, err = dhkem.Decap(make([]byte, 10), skR)
	require.Error(t, err)
}

func TestDeriveKeyPair(t *testing.T) {
	ikm := make([]byte, 64)
	for i := range ikm {
		ikm[i] = byte(i)
	}

	sk1, err := dhkem.DeriveKeyPair(ikm)
	require.NoError(t, err)

	// Deterministic: same ikm → same key
	sk2, err := dhkem.DeriveKeyPair(ikm)
	require.NoError(t, err)
	require.Equal(t, sk1.Bytes(), sk2.Bytes())
	require.Equal(t, sk1.PublicKey().Bytes(), sk2.PublicKey().Bytes())

	// Different ikm → different key
	ikm[0] = 0xFF
	sk3, err := dhkem.DeriveKeyPair(ikm)
	require.NoError(t, err)
	require.NotEqual(t, sk1.Bytes(), sk3.Bytes())
}

func TestDeriveKeyPairTooShort(t *testing.T) {
	_, err := dhkem.DeriveKeyPair(make([]byte, 10))
	require.Error(t, err)
}

// Fuzz tests

// FuzzEncapDecap verifies that for any generated recipient key,
// Encap and Decap always agree on the shared secret.
func FuzzEncapDecap(f *testing.F) {
	f.Add(make([]byte, dhkem.Nsk))

	seed := make([]byte, dhkem.Nsk)
	for i := range seed {
		seed[i] = byte(i * 37)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, skBytes []byte) {
		if len(skBytes) != dhkem.Nsk {
			t.Skip()
		}

		skR, err := dhkem.NewPrivateKey(skBytes)
		if err != nil {
			t.Skip()
		}

		ss, enc, err := dhkem.Encap(skR.PublicKey())
		if err != nil {
			// Low-order public key — acceptable
			t.Skip()
		}

		ss2, err := dhkem.Decap(enc, skR)
		if err != nil {
			t.Fatalf("Decap failed after successful Encap: %v", err)
		}

		if len(ss) != dhkem.Nsecret {
			t.Fatalf("shared secret length %d, want %d", len(ss), dhkem.Nsecret)
		}
		if len(ss2) != dhkem.Nsecret {
			t.Fatalf("decap shared secret length %d, want %d", len(ss2), dhkem.Nsecret)
		}
		for i := range ss {
			if ss[i] != ss2[i] {
				t.Fatal("shared secrets do not match")
			}
		}
	})
}

// FuzzNewPublicKey verifies NewPublicKey never panics on arbitrary input.
func FuzzNewPublicKey(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, dhkem.Npk))
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		pk, err := dhkem.NewPublicKey(data)
		if err != nil {
			return
		}
		if len(pk.Bytes()) != dhkem.Npk {
			t.Fatalf("public key bytes length %d, want %d", len(pk.Bytes()), dhkem.Npk)
		}
	})
}

// FuzzNewPrivateKey verifies NewPrivateKey never panics on arbitrary input
// and that roundtripping always preserves the public key relationship.
func FuzzNewPrivateKey(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, dhkem.Nsk))
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		sk, err := dhkem.NewPrivateKey(data)
		if err != nil {
			return
		}

		// Roundtrip: re-derive from serialized bytes must match
		sk2, err := dhkem.NewPrivateKey(sk.Bytes())
		if err != nil {
			t.Fatalf("roundtrip NewPrivateKey failed: %v", err)
		}

		if string(sk.Bytes()) != string(sk2.Bytes()) {
			t.Fatal("private key roundtrip mismatch")
		}
		if string(sk.PublicKey().Bytes()) != string(sk2.PublicKey().Bytes()) {
			t.Fatal("public key roundtrip mismatch")
		}
	})
}

// FuzzDecap verifies Decap never panics on arbitrary encapsulated keys.
func FuzzDecap(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, dhkem.Nenc))
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, enc []byte) {
		sk, err := dhkem.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}

		// Should not panic regardless of input
		_, _ = dhkem.Decap(enc, sk)
	})
}

// FuzzDeriveKeyPair verifies DeriveKeyPair never panics and is deterministic.
func FuzzDeriveKeyPair(f *testing.F) {
	f.Add(make([]byte, dhkem.Nsk))
	f.Add(make([]byte, 128))

	f.Fuzz(func(t *testing.T, ikm []byte) {
		sk1, err := dhkem.DeriveKeyPair(ikm)
		if err != nil {
			return
		}

		sk2, err := dhkem.DeriveKeyPair(ikm)
		if err != nil {
			t.Fatal("DeriveKeyPair not deterministic: second call failed")
		}

		if string(sk1.Bytes()) != string(sk2.Bytes()) {
			t.Fatal("DeriveKeyPair not deterministic: different private keys")
		}
		if string(sk1.PublicKey().Bytes()) != string(sk2.PublicKey().Bytes()) {
			t.Fatal("DeriveKeyPair not deterministic: different public keys")
		}
	})
}
