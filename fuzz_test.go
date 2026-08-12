package x448_test

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	circlx448 "github.com/cloudflare/circl/dh/x448"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"

	// Register X448 support
	x448mod "github.com/jwx-go/x448/v4"
)

// FuzzECDHESEncryptAndDecrypt verifies that for any payload, encrypting with
// ECDH-ES against an X448 public key and decrypting with the matching
// private key always recovers the original payload. The key pair is
// generated once in the seed stage; only the payload is fuzzed.
func FuzzECDHESEncryptAndDecrypt(f *testing.F) {
	var seed circlx448.Key
	if _, err := rand.Read(seed[:]); err != nil {
		f.Fatal(err)
	}
	privKey := x448mod.NewPrivateKey(seed)

	privJWK, err := jwk.Import[jwk.OKPPrivateKey](privKey)
	if err != nil {
		f.Fatal(err)
	}

	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(``))
	f.Add([]byte(`{"msg":"hello"}`))
	f.Add([]byte(`Hello, X448 ECDH-ES!`))
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, payload []byte) {
		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.ECDH_ES(), pubJWK),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "encryption failed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.ECDH_ES(), privJWK),
		)
		require.NoError(t, err, "decryption failed")

		// jwe.Decrypt returns a nil slice for a zero-length plaintext, so
		// compare as strings rather than raw byte slices.
		require.Equal(t, string(payload), string(decrypted))
	})
}

// FuzzDecryptMalformed verifies that jwe.Decrypt never panics on arbitrary
// input and, whenever it does succeed, returns exactly the plaintext that
// was genuinely encrypted for the given X448 private key. The key pair and
// the genuine JWEs are built once in the seed stage; only the ciphertext
// bytes handed to jwe.Decrypt are fuzzed. Garbage input is expected to be
// rejected with an error, which is not itself a failure.
func FuzzDecryptMalformed(f *testing.F) {
	var seed circlx448.Key
	if _, err := rand.Read(seed[:]); err != nil {
		f.Fatal(err)
	}
	privKey := x448mod.NewPrivateKey(seed)

	privJWK, err := jwk.Import[jwk.OKPPrivateKey](privKey)
	if err != nil {
		f.Fatal(err)
	}

	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		f.Fatal(err)
	}

	plaintext := []byte("seed plaintext for FuzzDecryptMalformed")

	genuineECDHES, err := jwe.Encrypt(plaintext,
		jwe.WithKey(jwa.ECDH_ES(), pubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		f.Fatal(err)
	}

	genuineHPKE, err := jwe.Encrypt(plaintext,
		jwe.WithKey(x448mod.HPKE5(), pubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		f.Fatal(err)
	}

	truncated := genuineECDHES[:len(genuineECDHES)/2]

	bitFlipped := make([]byte, len(genuineECDHES))
	copy(bitFlipped, genuineECDHES)
	bitFlipped[len(bitFlipped)/2] ^= 0x01

	f.Add(genuineECDHES)
	f.Add(genuineHPKE)
	f.Add([]byte(``))
	f.Add([]byte(`not-a-jwe`))
	f.Add(truncated)
	f.Add(bitFlipped)

	f.Fuzz(func(t *testing.T, data []byte) {
		decrypted, err := jwe.Decrypt(data,
			jwe.WithKey(jwa.ECDH_ES(), privJWK),
			jwe.WithKey(x448mod.HPKE5(), privJWK),
		)
		if err != nil {
			// Rejecting garbage is the expected outcome.
			return
		}

		require.Equal(t, string(plaintext), string(decrypted),
			"a mismatch here would mean forged or tampered ciphertext was accepted")
	})
}

// FuzzParseJWK verifies that jwk.ParseKey never panics on arbitrary input,
// and that a successfully parsed OKP X448 key can be marshaled back to JSON
// and re-parsed without panicking.
func FuzzParseJWK(f *testing.F) {
	var seed circlx448.Key
	if _, err := rand.Read(seed[:]); err != nil {
		f.Fatal(err)
	}
	privKey := x448mod.NewPrivateKey(seed)

	privJWK, err := jwk.Import[jwk.OKPPrivateKey](privKey)
	if err != nil {
		f.Fatal(err)
	}

	genuine, err := json.Marshal(privJWK)
	if err != nil {
		f.Fatal(err)
	}

	truncated := genuine[:len(genuine)/2]

	mutated := make([]byte, len(genuine))
	copy(mutated, genuine)
	mutated[len(mutated)/2] ^= 0x01

	f.Add(genuine)
	f.Add([]byte(``))
	f.Add([]byte(`not-json`))
	f.Add(truncated)
	f.Add(mutated)

	f.Fuzz(func(_ *testing.T, data []byte) {
		key, err := jwk.ParseKey(data)
		if err != nil {
			return
		}

		buf, err := json.Marshal(key)
		if err != nil {
			return
		}
		_, _ = jwk.ParseKey(buf)
	})
}
