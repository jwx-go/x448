package x448_test

import (
	"crypto/rand"
	"testing"

	circlx448 "github.com/cloudflare/circl/dh/x448"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"

	// Register X448 support
	x448mod "github.com/jwx-go/x448/v4"
)

func TestJWKRoundtrip(t *testing.T) {
	var seed circlx448.Key
	_, err := rand.Read(seed[:])
	require.NoError(t, err)

	privKey := x448mod.NewPrivateKey(seed)

	// Import private key to JWK
	privJWK, err := jwk.Import[jwk.OKPPrivateKey](privKey)
	require.NoError(t, err)
	require.Equal(t, jwa.OKP(), privJWK.KeyType())

	crv, ok := privJWK.Crv()
	require.True(t, ok)
	require.Equal(t, jwa.X448(), crv)

	// Export back to raw
	rawPriv, err := jwk.Export[*x448mod.PrivateKey](privJWK)
	require.NoError(t, err)
	require.Equal(t, privKey.Seed(), rawPriv.Seed())
	require.Equal(t, privKey.PublicKeyBytes(), rawPriv.PublicKeyBytes())

	// Import public key to JWK
	pubKey := privKey.Public()
	pubJWK, err := jwk.Import[jwk.OKPPublicKey](pubKey)
	require.NoError(t, err)
	require.Equal(t, jwa.OKP(), pubJWK.KeyType())

	// Export back to raw
	rawPub, err := jwk.Export[*x448mod.PublicKey](pubJWK)
	require.NoError(t, err)
	require.Equal(t, pubKey.Bytes(), rawPub.Bytes())
}

func TestJWKPublicKeyFromPrivate(t *testing.T) {
	var seed circlx448.Key
	_, err := rand.Read(seed[:])
	require.NoError(t, err)

	var pub circlx448.Key
	circlx448.KeyGen(&pub, &seed)

	privKey := x448mod.NewPrivateKey(seed)
	privJWK, err := jwk.Import[jwk.OKPPrivateKey](privKey)
	require.NoError(t, err)

	pubJWK, err := privJWK.PublicKey()
	require.NoError(t, err)

	rawPub, err := jwk.Export[*x448mod.PublicKey](pubJWK)
	require.NoError(t, err)
	require.Equal(t, pub[:], rawPub.Bytes())
}

func TestJWE_ECDH_ES(t *testing.T) {
	testCases := []struct {
		name string
		alg  jwa.KeyEncryptionAlgorithm
		enc  jwa.ContentEncryptionAlgorithm
	}{
		{"ECDH-ES/A128GCM", jwa.ECDH_ES(), jwa.A128GCM()},
		{"ECDH-ES/A256GCM", jwa.ECDH_ES(), jwa.A256GCM()},
		{"ECDH-ES/A128CBC-HS256", jwa.ECDH_ES(), jwa.A128CBC_HS256()},
		{"ECDH-ES+A128KW/A128GCM", jwa.ECDH_ES_A128KW(), jwa.A128GCM()},
		{"ECDH-ES+A192KW/A192GCM", jwa.ECDH_ES_A192KW(), jwa.A192GCM()},
		{"ECDH-ES+A256KW/A256GCM", jwa.ECDH_ES_A256KW(), jwa.A256GCM()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var seed circlx448.Key
			_, err := rand.Read(seed[:])
			require.NoError(t, err)

			privKey := x448mod.NewPrivateKey(seed)

			// Import to JWK
			privJWK, err := jwk.Import[jwk.OKPPrivateKey](privKey)
			require.NoError(t, err)

			payload := []byte("Hello, X448 ECDH-ES!")

			// Encrypt using the public key
			pubJWK, err := privJWK.PublicKey()
			require.NoError(t, err)

			encrypted, err := jwe.Encrypt(payload,
				jwe.WithKey(tc.alg, pubJWK),
				jwe.WithContentEncryption(tc.enc),
			)
			require.NoError(t, err, "encryption failed")

			// Decrypt using the private key
			decrypted, err := jwe.Decrypt(encrypted,
				jwe.WithKey(tc.alg, privJWK),
			)
			require.NoError(t, err, "decryption failed")
			require.Equal(t, payload, decrypted)
		})
	}
}

func TestJWE_ECDH_ES_RawKeys(t *testing.T) {
	var seed circlx448.Key
	_, err := rand.Read(seed[:])
	require.NoError(t, err)

	privKey := x448mod.NewPrivateKey(seed)
	pubKey := privKey.Public()

	payload := []byte("Hello, X448 raw keys!")

	// Encrypt using raw public key wrapper (via JWK)
	pubJWK, err := jwk.Import[jwk.OKPPublicKey](pubKey)
	require.NoError(t, err)

	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(jwa.ECDH_ES(), pubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	require.NoError(t, err)

	// Decrypt using raw private key wrapper (via JWK)
	privJWK, err := jwk.Import[jwk.OKPPrivateKey](privKey)
	require.NoError(t, err)

	decrypted, err := jwe.Decrypt(encrypted,
		jwe.WithKey(jwa.ECDH_ES(), privJWK),
	)
	require.NoError(t, err)
	require.Equal(t, payload, decrypted)
}

func TestJWE_HPKE(t *testing.T) {
	testCases := []struct {
		name string
		alg  jwa.KeyEncryptionAlgorithm
		enc  jwa.ContentEncryptionAlgorithm
	}{
		{"HPKE-5-KE/A128GCM", x448mod.HPKE5(), jwa.A128GCM()},
		{"HPKE-5-KE/A256GCM", x448mod.HPKE5(), jwa.A256GCM()},
		{"HPKE-5-KE/A128CBC-HS256", x448mod.HPKE5(), jwa.A128CBC_HS256()},
		{"HPKE-5-KE/A256CBC-HS512", x448mod.HPKE5(), jwa.A256CBC_HS512()},
		{"HPKE-6-KE/A128GCM", x448mod.HPKE6(), jwa.A128GCM()},
		{"HPKE-6-KE/A256GCM", x448mod.HPKE6(), jwa.A256GCM()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var seed circlx448.Key
			_, err := rand.Read(seed[:])
			require.NoError(t, err)

			privKey := x448mod.NewPrivateKey(seed)

			privJWK, err := jwk.Import[jwk.Key](privKey)
			require.NoError(t, err)

			pubJWK, err := privJWK.PublicKey()
			require.NoError(t, err)

			payload := []byte("Hello, X448 HPKE!")

			encrypted, err := jwe.Encrypt(payload,
				jwe.WithKey(tc.alg, pubJWK),
				jwe.WithContentEncryption(tc.enc),
			)
			require.NoError(t, err, "encryption failed")

			decrypted, err := jwe.Decrypt(encrypted,
				jwe.WithKey(tc.alg, privJWK),
			)
			require.NoError(t, err, "decryption failed")
			require.Equal(t, payload, decrypted)
		})
	}
}

// TestECDH_LowOrderRejection locks in the RFC 7748 §6.2 guard: feeding an
// all-zero (low-order) X448 public key into the ECDH-ES path must fail rather
// than silently producing an all-zero shared secret. If a future backend swap
// drops the !x448.Shared(...) check, this test fails instead of the library
// quietly accepting attacker-chosen low-order peers.
func TestECDH_LowOrderRejection(t *testing.T) {
	var zero circlx448.Key // all-zero point, rejected by x448.Shared

	t.Run("GenerateECDHES rejects low-order peer public key", func(t *testing.T) {
		peer := x448mod.NewPublicKey(zero)
		_, _, err := peer.GenerateECDHES("ECDH-ES", 32, nil, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "low-order public key")
	})

	t.Run("DeriveECDHES rejects low-order ephemeral public key", func(t *testing.T) {
		var seed circlx448.Key
		_, err := rand.Read(seed[:])
		require.NoError(t, err)
		priv := x448mod.NewPrivateKey(seed)

		ephPub := x448mod.NewPublicKey(zero)
		_, err = priv.DeriveECDHES("ECDH-ES", 32, ephPub, nil, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "low-order ephemeral key")
	})
}
