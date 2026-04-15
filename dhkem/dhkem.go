// Package dhkem implements DHKEM(X448, HKDF-SHA512) as defined in
// RFC 9180, Section 4.1.
//
// Go's standard library crypto/hpke does not support DHKEM(X448)
// (KEM ID 0x0021), so this package provides the implementation using
// github.com/cloudflare/circl/dh/x448.
//
// The implementation follows RFC 9180 exactly:
//   - KEM ID: 0x0021
//   - Nsecret: 64
//   - Nenc: 56
//   - Npk: 56
//   - Nsk: 56
//   - KDF: HKDF-SHA512
package dhkem

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/dh/x448"
	"golang.org/x/crypto/hkdf"
)

const (
	// KEMID is the HPKE KEM identifier for DHKEM(X448, HKDF-SHA512).
	KEMID uint16 = 0x0021

	// Nsecret is the length in bytes of the shared secret.
	Nsecret = 64

	// Nenc is the length in bytes of the serialized encapsulated key.
	Nenc = x448.Size // 56

	// Npk is the length in bytes of a serialized public key.
	Npk = x448.Size // 56

	// Nsk is the length in bytes of a serialized private key.
	Nsk = x448.Size // 56
)

// suiteID is "KEM" || I2OSP(0x0021, 2) per RFC 9180, Section 4.
var suiteID = []byte{
	'K', 'E', 'M',
	0x00, 0x21,
}

// PublicKey is a DHKEM(X448) public key.
type PublicKey struct {
	key x448.Key
}

// Bytes serializes the public key (SerializePublicKey per RFC 9180).
func (pk *PublicKey) Bytes() []byte {
	out := make([]byte, Npk)
	copy(out, pk.key[:])
	return out
}

// PrivateKey is a DHKEM(X448) private key.
type PrivateKey struct {
	seed x448.Key
	pub  PublicKey
}

// PublicKey returns the corresponding public key.
func (sk *PrivateKey) PublicKey() *PublicKey {
	return &sk.pub
}

// Bytes serializes the private key (SerializePrivateKey per RFC 9180).
func (sk *PrivateKey) Bytes() []byte {
	out := make([]byte, Nsk)
	copy(out, sk.seed[:])
	return out
}

// GenerateKey generates a random DHKEM(X448) key pair.
func GenerateKey() (*PrivateKey, error) {
	return generateKey(rand.Reader)
}

func generateKey(rng io.Reader) (*PrivateKey, error) {
	var seed x448.Key
	if _, err := io.ReadFull(rng, seed[:]); err != nil {
		return nil, fmt.Errorf("dhkem: failed to generate random bytes: %w", err)
	}
	return newPrivateKey(seed), nil
}

func newPrivateKey(seed x448.Key) *PrivateKey {
	sk := &PrivateKey{seed: seed}
	x448.KeyGen(&sk.pub.key, &sk.seed)
	return sk
}

// NewPublicKey deserializes a public key from bytes
// (DeserializePublicKey per RFC 9180).
func NewPublicKey(data []byte) (*PublicKey, error) {
	if len(data) != Npk {
		return nil, fmt.Errorf("dhkem: invalid public key size %d (expected %d)", len(data), Npk)
	}
	pk := &PublicKey{}
	copy(pk.key[:], data)
	return pk, nil
}

// NewPrivateKey deserializes a private key from bytes
// (DeserializePrivateKey per RFC 9180).
func NewPrivateKey(data []byte) (*PrivateKey, error) {
	if len(data) != Nsk {
		return nil, fmt.Errorf("dhkem: invalid private key size %d (expected %d)", len(data), Nsk)
	}
	var seed x448.Key
	copy(seed[:], data)
	return newPrivateKey(seed), nil
}

// DeriveKeyPair derives a key pair from input keying material
// per RFC 9180, Section 7.1.3 (DeriveKeyPairFromScalar for X448).
func DeriveKeyPair(ikm []byte) (*PrivateKey, error) {
	if len(ikm) < Nsk {
		return nil, fmt.Errorf("dhkem: ikm too short %d (need at least %d)", len(ikm), Nsk)
	}

	dkpPrk := labeledExtract([]byte("dkp_prk"), ikm)
	skBytes := labeledExpand(dkpPrk, []byte("sk"), nil, Nsk)

	var seed x448.Key
	copy(seed[:], skBytes)
	return newPrivateKey(seed), nil
}

// Encap generates a shared secret and an encapsulated key for the
// given recipient public key (Encap per RFC 9180, Section 4.1).
func Encap(pkR *PublicKey) (sharedSecret []byte, enc []byte, err error) {
	skE, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return encap(skE, pkR)
}

func encap(skE *PrivateKey, pkR *PublicKey) ([]byte, []byte, error) {
	dh, err := doDH(skE, pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("dhkem: Encap: %w", err)
	}

	enc := skE.PublicKey().Bytes()

	kemContext := make([]byte, 0, Nenc+Npk)
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, pkR.Bytes()...)

	sharedSecret := extractAndExpand(dh, kemContext)
	return sharedSecret, enc, nil
}

// Decap recovers the shared secret from an encapsulated key and the
// recipient's private key (Decap per RFC 9180, Section 4.1).
func Decap(enc []byte, skR *PrivateKey) ([]byte, error) {
	pkE, err := NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("dhkem: Decap: %w", err)
	}

	dh, err := doDH(skR, pkE)
	if err != nil {
		return nil, fmt.Errorf("dhkem: Decap: %w", err)
	}

	kemContext := make([]byte, 0, Nenc+Npk)
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, skR.PublicKey().Bytes()...)

	sharedSecret := extractAndExpand(dh, kemContext)
	return sharedSecret, nil
}

// doDH performs the X448 Diffie-Hellman operation.
func doDH(sk *PrivateKey, pk *PublicKey) ([]byte, error) {
	// x448.Shared returns false on low-order / all-zero-output inputs; this is
	// our RFC 7748 §6.2 guard and must be preserved across backend updates.
	var shared x448.Key
	if !x448.Shared(&shared, &sk.seed, &pk.key) {
		return nil, fmt.Errorf("DH failed (low-order point)")
	}
	return shared[:], nil
}

// extractAndExpand performs ExtractAndExpand per RFC 9180, Section 4.1:
//
//	eae_prk = LabeledExtract("", "eae_prk", dh)
//	shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
func extractAndExpand(dh, kemContext []byte) []byte {
	prk := labeledExtract([]byte("eae_prk"), dh)
	return labeledExpand(prk, []byte("shared_secret"), kemContext, Nsecret)
}

// labeledExtract per RFC 9180, Section 4:
//
//	LabeledExtract(salt, label, ikm) =
//	  Extract(salt, concat("HPKE-v1", suite_id, label, ikm))
//
// DHKEM(X448, HKDF-SHA512) always uses an empty salt, so the salt
// parameter from the spec is omitted here.
func labeledExtract(label, ikm []byte) []byte {
	labeled := buildLabeledIKM(label, ikm)
	return hkdfExtract(nil, labeled)
}

// labeledExpand per RFC 9180, Section 4:
//
//	LabeledExpand(prk, label, info, L) =
//	  Expand(prk, concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info), L)
func labeledExpand(prk, label, info []byte, length int) []byte {
	labeledInfo := buildLabeledInfo(label, info, length)
	return hkdfExpand(prk, labeledInfo, length)
}

func buildLabeledIKM(label, ikm []byte) []byte {
	// "HPKE-v1" || suite_id || label || ikm
	hpkeV1 := []byte("HPKE-v1")
	buf := make([]byte, 0, len(hpkeV1)+len(suiteID)+len(label)+len(ikm))
	buf = append(buf, hpkeV1...)
	buf = append(buf, suiteID...)
	buf = append(buf, label...)
	buf = append(buf, ikm...)
	return buf
}

func buildLabeledInfo(label, info []byte, length int) []byte {
	// I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
	hpkeV1 := []byte("HPKE-v1")
	buf := make([]byte, 0, 2+len(hpkeV1)+len(suiteID)+len(label)+len(info))
	buf = append(buf, byte(length>>8), byte(length))
	buf = append(buf, hpkeV1...)
	buf = append(buf, suiteID...)
	buf = append(buf, label...)
	buf = append(buf, info...)
	return buf
}

// hkdfExtract is HKDF-Extract with SHA-512.
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, crypto.SHA512.Size())
	}
	return hkdf.Extract(crypto.SHA512.New, ikm, salt)
}

// hkdfExpand is HKDF-Expand with SHA-512.
func hkdfExpand(prk, info []byte, length int) []byte {
	r := hkdf.Expand(crypto.SHA512.New, prk, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("dhkem: HKDF-Expand failed: " + err.Error())
	}
	return out
}
