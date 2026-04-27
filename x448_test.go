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
		_, _, err := peer.GenerateECDHES("A256GCM", 32, nil, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "low-order public key")
	})

	t.Run("DeriveECDHES rejects low-order ephemeral public key", func(t *testing.T) {
		var seed circlx448.Key
		_, err := rand.Read(seed[:])
		require.NoError(t, err)
		priv := x448mod.NewPrivateKey(seed)

		ephPub := x448mod.NewPublicKey(zero)
		_, err = priv.DeriveECDHES("A256GCM", 32, ephPub, nil, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "low-order ephemeral key")
	})
}

// TestECDHESAlgGuard locks in the defensive whitelist on GenerateECDHES and
// DeriveECDHES. jwebb hands in the *derivedAlg* — the JWE "enc" for direct
// ECDH-ES, the "alg" for the ECDH-ES+A*KW variants — so anything outside
// that set (HPKE-*, RSA-*, dir, PBES2-*, the outer "ECDH-ES" identifier,
// etc.) must fail loudly instead of reaching the derivation helper.
func TestECDHESAlgGuard(t *testing.T) {
	var seed circlx448.Key
	_, err := rand.Read(seed[:])
	require.NoError(t, err)

	priv := x448mod.NewPrivateKey(seed)
	pub := priv.Public()

	rejected := []string{"HPKE-5-KE", "RSA-OAEP", "dir", "PBES2-HS256+A128KW", "ECDH-ES", "A128KW", "", "a128gcm"}
	for _, alg := range rejected {
		t.Run("GenerateECDHES/"+alg, func(t *testing.T) {
			_, _, err := pub.GenerateECDHES(alg, 32, nil, nil)
			require.Error(t, err)
			require.ErrorContains(t, err, "unsupported ECDH-ES derivedAlg")
		})
		t.Run("DeriveECDHES/"+alg, func(t *testing.T) {
			_, err := priv.DeriveECDHES(alg, 32, pub, nil, nil)
			require.Error(t, err)
			require.ErrorContains(t, err, "unsupported ECDH-ES derivedAlg")
		})
	}

	// Happy-path sanity: every alg jwebb actually passes in must still work.
	// These are the direct-mode enc algs plus the ECDH-ES+A*KW variants.
	accepted := []string{
		"A128GCM", "A192GCM", "A256GCM",
		"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
		"ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
	}
	for _, alg := range accepted {
		t.Run("GenerateECDHES_accept/"+alg, func(t *testing.T) {
			_, _, err := pub.GenerateECDHES(alg, 32, nil, nil)
			require.NoError(t, err)
		})
	}
}

// TestECDHESAlgGuardAcceptsCustomContentEncryption pins that
// validateECDHESAlg delegates to jwa.LookupContentEncryptionAlgorithm
// instead of hardcoding the canonical AES-CBC-HMAC / GCM names. A
// caller registering a new content-encryption alg (e.g. via
// jwa.RegisterContentEncryptionAlgorithm) used to find that X448's
// ECDH-ES dispatch refused it with "unsupported ECDH-ES derivedAlg"
// while X25519 (going through stdlib) silently accepted it. After
// the fix, the X448 path tracks jwa's vocabulary and accepts any
// registered ContentEncryption value the dispatcher passes in.
func TestECDHESAlgGuardAcceptsCustomContentEncryption(t *testing.T) {
	const customAlg = "TESTALG-CE-X448-001"
	custom := jwa.NewContentEncryptionAlgorithm(customAlg)
	require.NoError(t, jwa.RegisterContentEncryptionAlgorithm(custom))
	t.Cleanup(func() { jwa.UnregisterContentEncryptionAlgorithm(custom) })

	var seed circlx448.Key
	_, err := rand.Read(seed[:])
	require.NoError(t, err)
	priv := x448mod.NewPrivateKey(seed)
	pub := priv.Public()

	t.Run("GenerateECDHES accepts custom ContentEncryption", func(t *testing.T) {
		_, _, err := pub.GenerateECDHES(customAlg, 32, nil, nil)
		require.NoError(t, err,
			`X448 ECDH-ES dispatch must accept newly-registered ContentEncryption algs`)
	})

	t.Run("DeriveECDHES accepts custom ContentEncryption", func(t *testing.T) {
		_, ephPubAny, err := pub.GenerateECDHES(customAlg, 32, nil, nil)
		require.NoError(t, err)
		ephPub, ok := ephPubAny.(*x448mod.PublicKey)
		require.True(t, ok)
		_, err = priv.DeriveECDHES(customAlg, 32, ephPub, nil, nil)
		require.NoError(t, err)
	})
}

// TestJWKImportRejectsNilTypedPointers pins that jwk.Import on a
// typed-nil *x448.PublicKey or *x448.PrivateKey does not panic.
// The pointer arms of importX448RawKey previously dereferenced
// k.key[:] / k.pub[:] / k.seed[:] without checking k for nil; a
// caller passing var p *x448.PublicKey (nil) to jwk.Import
// crashes the host process.
//
// Misuse-only path — a sane caller wouldn't construct a nil typed
// pointer and pass it to jwk.Import — but the importer's contract
// is "I tell jwk whether I accept this value", so returning false
// is the correct response. A panic from a misuse-shaped input is a
// robustness defect.
func TestJWKImportRejectsNilTypedPointers(t *testing.T) {
	t.Run("nil *PublicKey", func(t *testing.T) {
		var p *x448mod.PublicKey
		_, err := jwk.Import[jwk.Key](p)
		require.Error(t, err, `jwk.Import must reject a nil typed *PublicKey without panicking`)
	})

	t.Run("nil *PrivateKey", func(t *testing.T) {
		var p *x448mod.PrivateKey
		_, err := jwk.Import[jwk.Key](p)
		require.Error(t, err, `jwk.Import must reject a nil typed *PrivateKey without panicking`)
	})
}
