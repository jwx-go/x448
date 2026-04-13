// Package x448 provides X448 ECDH-ES key agreement, HPKE, and JWK support
// for the jwx library.
//
// X448 is not included in the main jwx module because Go's standard library
// does not support X448, requiring the external github.com/cloudflare/circl
// module. To avoid adding this dependency for all users, X448 support is
// provided as a separate module.
//
// To enable X448 support, import this package for its side effects:
//
//	import _ "github.com/jwx-go/x448/v4"
//
// This registers X448 JWK key import/export, ECDH-ES key agreement, and
// HPKE algorithms (HPKE-5-KE, HPKE-6-KE) with the jwx library. After
// importing, OKP keys with curve "X448" can be used with jwe.Encrypt and
// jwe.Decrypt using ECDH-ES and HPKE algorithms.
//
// Registration happens in init(). If any underlying jwx Register* call
// returns an error, init() panics — importing this package will crash the
// program at load time. This is the house style across all jwx-go extension
// modules.
package x448

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkunsafe"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"

	x448hpke "github.com/jwx-go/x448/v4/hpke"
	"github.com/jwx-go/x448/v4/dhkem"
)

// HPKE algorithm identifiers per draft-ietf-jose-hpke-encrypt.
const (
	// HPKE5KE is DHKEM(X448, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM.
	HPKE5KE = "HPKE-5-KE"

	// HPKE6KE is DHKEM(X448, HKDF-SHA512) + HKDF-SHA512 + ChaCha20Poly1305.
	HPKE6KE = "HPKE-6-KE"
)

var x448Curve = jwa.X448()

var hpke5ke = jwa.NewKeyEncryptionAlgorithm(HPKE5KE)
var hpke6ke = jwa.NewKeyEncryptionAlgorithm(HPKE6KE)

// HPKE5() returns the HPKE-5-KE key encryption algorithm.
func HPKE5() jwa.KeyEncryptionAlgorithm { return hpke5ke }

// HPKE6() returns the HPKE-6-KE key encryption algorithm.
func HPKE6() jwa.KeyEncryptionAlgorithm { return hpke6ke }

func init() {
	// Register JWK exporter for OKP:X448 keys (JWK → raw x448 key)
	panicOnRegistrationError(jwk.RegisterKeyExporter(jwk.KeyKind("OKP:X448"), jwk.KeyExportFunc(exportX448Key)))

	// Register raw key importer for X448 keys
	panicOnRegistrationError(jwk.RegisterOKPRawKeyImporter(importX448RawKey))

	// Register jwk.Import handlers for X448 key types (raw x448 key → JWK)
	panicOnRegistrationError(jwk.RegisterKeyImporter(importX448PublicKey))
	panicOnRegistrationError(jwk.RegisterKeyImporter(importX448PrivateKey))

	// Register HPKE key encryption algorithms
	panicOnRegistrationError(jwa.RegisterKeyEncryptionAlgorithm(hpke5ke))
	panicOnRegistrationError(jwa.RegisterKeyEncryptionAlgorithm(hpke6ke))

	// Register as HPKE algorithms so IsHPKE() returns true
	panicOnRegistrationError(jwebb.RegisterHPKEAlgorithm(HPKE5KE))
	panicOnRegistrationError(jwebb.RegisterHPKEAlgorithm(HPKE6KE))
}

// panicOnRegistrationError converts a non-nil error returned by a jwx
// Register* call during init() into an import-time panic. The rule
// (documented in jwx's internals.md) is that a failed Register* leaves
// the extension unusable, so we surface it immediately instead of
// letting the program continue in a broken state.
func panicOnRegistrationError(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwx-go/x448: registration failed: %s", err))
	}
}

// hpkeAEAD maps an HPKE algorithm identifier to the corresponding AEAD.
func hpkeAEAD(alg string) (x448hpke.AEAD, error) {
	switch alg {
	case HPKE5KE:
		return x448hpke.AES256GCM, nil
	case HPKE6KE:
		return x448hpke.ChaCha20Poly1305, nil
	default:
		return 0, fmt.Errorf("x448: unsupported HPKE algorithm %s", alg)
	}
}

// hpkeKEInfo builds the HPKE info parameter for Key Encryption mode
// per draft-ietf-jose-hpke-encrypt:
//
//	"JOSE-HPKE rcpt" || 0xFF || enc_value || 0xFF
func hpkeKEInfo(calg string) []byte {
	prefix := []byte("JOSE-HPKE rcpt")
	calgBytes := []byte(calg)
	info := make([]byte, 0, len(prefix)+1+len(calgBytes)+1)
	info = append(info, prefix...)
	info = append(info, 0xFF)
	info = append(info, calgBytes...)
	info = append(info, 0xFF)
	return info
}

// --- Key wrapper types (implement ECDHESKeyGenerator/ECDHESKeyDeriver) ---

// PublicKey wraps a raw X448 public key and implements jwebb.ECDHESKeyGenerator
// for JWE ECDH-ES encryption.
type PublicKey struct {
	key x448.Key
}

// PrivateKey wraps a raw X448 private key pair and implements
// jwebb.ECDHESKeyDeriver for JWE ECDH-ES decryption.
type PrivateKey struct {
	seed x448.Key
	pub  x448.Key
}

// NewPrivateKey creates a new PrivateKey from a seed and public key.
func NewPrivateKey(seed, pub x448.Key) *PrivateKey {
	return &PrivateKey{seed: seed, pub: pub}
}

// NewPublicKey creates a new PublicKey from a raw X448 public key.
func NewPublicKey(pub x448.Key) *PublicKey {
	return &PublicKey{key: pub}
}

// Public returns the public key corresponding to this private key.
func (pk *PrivateKey) Public() *PublicKey {
	return &PublicKey{key: pk.pub}
}

// Seed returns the private key seed bytes.
func (pk *PrivateKey) Seed() []byte {
	ret := make([]byte, x448.Size)
	copy(ret, pk.seed[:])
	return ret
}

// PublicKeyBytes returns the public key bytes for this private key.
func (pk *PrivateKey) PublicKeyBytes() []byte {
	ret := make([]byte, x448.Size)
	copy(ret, pk.pub[:])
	return ret
}

// Bytes returns the public key bytes.
func (pk *PublicKey) Bytes() []byte {
	ret := make([]byte, x448.Size)
	copy(ret, pk.key[:])
	return ret
}

// GenerateECDHES implements jwebb.ECDHESKeyGenerator. It generates an ephemeral
// X448 key pair, computes the ECDH shared secret, and derives the KEK via
// Concat KDF (SHA-256).
func (pk *PublicKey) GenerateECDHES(alg string, keysize int, apu, apv []byte) ([]byte, any, error) {
	var ephSeed x448.Key
	if _, err := rand.Read(ephSeed[:]); err != nil {
		return nil, nil, fmt.Errorf(`x448: failed to generate ephemeral key: %w`, err)
	}

	var ephPub x448.Key
	x448.KeyGen(&ephPub, &ephSeed)

	var shared x448.Key
	if !x448.Shared(&shared, &ephSeed, &pk.key) {
		return nil, nil, fmt.Errorf(`x448: ECDH failed (low-order public key)`)
	}

	derivedKey, err := jwebb.DeriveECDHESRaw(alg, shared[:], apu, apv, keysize)
	if err != nil {
		return nil, nil, fmt.Errorf(`x448: %w`, err)
	}

	return derivedKey, &PublicKey{key: ephPub}, nil
}

// DeriveECDHES implements jwebb.ECDHESKeyDeriver. It computes the ECDH shared
// secret using this private key and the given ephemeral public key, then
// derives the KEK via Concat KDF (SHA-256).
func (pk *PrivateKey) DeriveECDHES(alg string, keysize int, ephemeralPubKey any, apu, apv []byte) ([]byte, error) {
	var ephPub x448.Key
	switch epk := ephemeralPubKey.(type) {
	case *PublicKey:
		ephPub = epk.key
	case PublicKey:
		ephPub = epk.key
	default:
		return nil, fmt.Errorf(`x448: unexpected ephemeral public key type %T`, ephemeralPubKey)
	}

	var shared x448.Key
	if !x448.Shared(&shared, &pk.seed, &ephPub) {
		return nil, fmt.Errorf(`x448: ECDH failed (low-order ephemeral key)`)
	}

	derivedKey, err := jwebb.DeriveECDHESRaw(alg, shared[:], apu, apv, keysize)
	if err != nil {
		return nil, fmt.Errorf(`x448: %w`, err)
	}

	return derivedKey, nil
}

// --- HPKE (HPKEKeyEncrypter / HPKEKeyDecrypter) ---

// EncryptHPKE implements jwebb.HPKEKeyEncrypter. It encrypts the CEK using
// HPKE Base mode with DHKEM(X448, HKDF-SHA512).
func (pk *PublicKey) EncryptHPKE(cek []byte, alg, calg string) ([]byte, []byte, error) {
	aead, err := hpkeAEAD(alg)
	if err != nil {
		return nil, nil, err
	}

	dkPub, err := dhkem.NewPublicKey(pk.key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("x448: %w", err)
	}

	info := hpkeKEInfo(calg)
	enc, sealedCEK, err := x448hpke.Seal(dkPub, aead, info, nil, cek)
	if err != nil {
		return nil, nil, fmt.Errorf("x448: %w", err)
	}

	return sealedCEK, enc, nil
}

// DecryptHPKE implements jwebb.HPKEKeyDecrypter. It decrypts the sealed CEK
// using HPKE Base mode with DHKEM(X448, HKDF-SHA512).
func (pk *PrivateKey) DecryptHPKE(sealedCEK []byte, alg, calg string, enc []byte) ([]byte, error) {
	aead, err := hpkeAEAD(alg)
	if err != nil {
		return nil, err
	}

	dkPriv, err := dhkem.NewPrivateKey(pk.seed[:])
	if err != nil {
		return nil, fmt.Errorf("x448: %w", err)
	}

	info := hpkeKEInfo(calg)
	cek, err := x448hpke.Open(dkPriv, aead, enc, info, nil, sealedCEK)
	if err != nil {
		return nil, fmt.Errorf("x448: %w", err)
	}

	return cek, nil
}

// --- JWK key export (JWK → raw x448 key) ---

func exportX448Key(key jwk.Key, _ any) (any, error) {
	switch key := key.(type) {
	case jwk.OKPPrivateKey:
		x, ok := key.X()
		if !ok {
			return nil, fmt.Errorf(`missing "x" field`)
		}
		d, ok := key.D()
		if !ok {
			return nil, fmt.Errorf(`missing "d" field`)
		}
		if len(d) != x448.Size {
			return nil, fmt.Errorf(`x448: wrong private key seed size %d (expected %d)`, len(d), x448.Size)
		}
		if len(x) != x448.Size {
			return nil, fmt.Errorf(`x448: wrong public key size %d (expected %d)`, len(x), x448.Size)
		}

		var seed x448.Key
		copy(seed[:], d)

		// Verify x matches the public key derived from d
		var pub x448.Key
		x448.KeyGen(&pub, &seed)
		for i := range pub {
			if pub[i] != x[i] {
				return nil, fmt.Errorf(`x448: invalid x value given d value`)
			}
		}

		return &PrivateKey{seed: seed, pub: pub}, nil
	case jwk.OKPPublicKey:
		x, ok := key.X()
		if !ok {
			return nil, fmt.Errorf(`missing "x" field`)
		}
		if len(x) != x448.Size {
			return nil, fmt.Errorf(`x448: wrong public key size %d (expected %d)`, len(x), x448.Size)
		}
		var pub x448.Key
		copy(pub[:], x)
		return &PublicKey{key: pub}, nil
	default:
		return nil, jwk.ContinueError()
	}
}

// --- JWK raw key import ---

func importX448RawKey(key any) (jwa.EllipticCurveAlgorithm, []byte, []byte, bool) {
	switch k := key.(type) {
	case *PublicKey:
		return x448Curve, k.key[:], nil, true
	case PublicKey:
		return x448Curve, k.key[:], nil, true
	case *PrivateKey:
		return x448Curve, k.pub[:], k.seed[:], true
	case PrivateKey:
		return x448Curve, k.pub[:], k.seed[:], true
	}
	return jwa.InvalidEllipticCurve(), nil, nil, false
}

func importX448PrivateKey(src *PrivateKey) (jwk.Key, error) {
	key, err := jwkunsafe.NewKey(jwa.OKP())
	if err != nil {
		return nil, fmt.Errorf(`failed to create OKP private key: %w`, err)
	}
	if err := key.Set(jwk.OKPCrvKey, x448Curve); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.OKPXKey, src.pub[:]); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.OKPDKey, src.seed[:]); err != nil {
		return nil, err
	}
	return key, nil
}

func importX448PublicKey(src *PublicKey) (jwk.Key, error) {
	key, err := jwkunsafe.NewPublicKey(jwa.OKP())
	if err != nil {
		return nil, fmt.Errorf(`failed to create OKP public key: %w`, err)
	}
	if err := key.Set(jwk.OKPCrvKey, x448Curve); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.OKPXKey, src.key[:]); err != nil {
		return nil, err
	}
	return key, nil
}
