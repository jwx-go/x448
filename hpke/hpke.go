// Package hpke implements HPKE Base mode with DHKEM(X448, HKDF-SHA512)
// as defined in RFC 9180.
//
// Go's standard library crypto/hpke does not support DHKEM(X448), so
// this package provides a standalone implementation using the dhkem
// sub-package for the KEM and standard crypto primitives for KDF and AEAD.
//
// Only single-shot Seal/Open operations are supported, matching the
// usage pattern of JOSE HPKE (draft-ietf-jose-hpke-encrypt).
package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"

	"github.com/jwx-go/x448/v4/dhkem"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// AEAD identifies the AEAD algorithm.
type AEAD uint16

const (
	// AES256GCM is AES-256-GCM (AEAD ID 0x0002).
	AES256GCM AEAD = 0x0002

	// ChaCha20Poly1305 is ChaCha20-Poly1305 (AEAD ID 0x0003).
	ChaCha20Poly1305 AEAD = 0x0003
)

func (a AEAD) keySize() int {
	switch a {
	case AES256GCM:
		return 32
	case ChaCha20Poly1305:
		return 32
	default:
		return 0
	}
}

func (a AEAD) nonceSize() int {
	switch a {
	case AES256GCM:
		return 12
	case ChaCha20Poly1305:
		return 12
	default:
		return 0
	}
}

func (a AEAD) newCipher(key []byte) (cipher.AEAD, error) {
	switch a {
	case AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case ChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("hpke: unsupported AEAD 0x%04x", uint16(a))
	}
}

// mode_base = 0x00 per RFC 9180 Section 5.1.
const modeBase = 0x00

// KDF is HKDF-SHA512 (KDF ID 0x0003), fixed for DHKEM(X448).
const kdfID uint16 = 0x0003

// suiteID = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
func suiteID(aeadID AEAD) []byte {
	return []byte{
		'H', 'P', 'K', 'E',
		byte(dhkem.KEMID >> 8), byte(dhkem.KEMID),
		byte(kdfID >> 8), byte(kdfID),
		byte(aeadID >> 8), byte(aeadID),
	}
}

// Nk for HKDF-SHA512 = 64 (hash output size).
const extractSize = 64

// Seal encrypts plaintext using HPKE Base mode with DHKEM(X448, HKDF-SHA512).
//
// Returns the encapsulated key (enc) and the ciphertext (sealed plaintext).
// The info parameter is bound into the key schedule per RFC 9180.
// aad is the associated data for the AEAD operation.
func Seal(pkR *dhkem.PublicKey, aead AEAD, info, aad, plaintext []byte) (enc, ciphertext []byte, err error) {
	sharedSecret, enc, err := dhkem.Encap(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke.Seal: %w", err)
	}

	key, baseNonce, err := keySchedule(modeBase, sharedSecret, info, aead)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke.Seal: %w", err)
	}

	aeadCipher, err := aead.newCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke.Seal: %w", err)
	}

	ciphertext = aeadCipher.Seal(nil, baseNonce, plaintext, aad)
	return enc, ciphertext, nil
}

// Open decrypts ciphertext using HPKE Base mode with DHKEM(X448, HKDF-SHA512).
//
// enc is the encapsulated key from the sender. The info and aad parameters
// must match the values used during Seal.
func Open(skR *dhkem.PrivateKey, aead AEAD, enc, info, aad, ciphertext []byte) ([]byte, error) {
	sharedSecret, err := dhkem.Decap(enc, skR)
	if err != nil {
		return nil, fmt.Errorf("hpke.Open: %w", err)
	}

	key, baseNonce, err := keySchedule(modeBase, sharedSecret, info, aead)
	if err != nil {
		return nil, fmt.Errorf("hpke.Open: %w", err)
	}

	aeadCipher, err := aead.newCipher(key)
	if err != nil {
		return nil, fmt.Errorf("hpke.Open: %w", err)
	}

	plaintext, err := aeadCipher.Open(nil, baseNonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("hpke.Open: decryption failed: %w", err)
	}

	return plaintext, nil
}

// keySchedule implements the HPKE KeySchedule per RFC 9180, Section 5.1.
//
//	psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
//	info_hash   = LabeledExtract("", "info_hash", info)
//	ks_context  = concat(mode, psk_id_hash, info_hash)
//	secret      = LabeledExtract(shared_secret, "secret", psk)
//	key         = LabeledExpand(secret, "key", ks_context, Nk)
//	base_nonce  = LabeledExpand(secret, "base_nonce", ks_context, Nn)
//
// For Base mode: psk = "", psk_id = "".
func keySchedule(mode byte, sharedSecret, info []byte, aead AEAD) (key, baseNonce []byte, err error) {
	sid := suiteID(aead)

	pskIDHash := labeledExtract(sid, nil, []byte("psk_id_hash"), nil)
	infoHash := labeledExtract(sid, nil, []byte("info_hash"), info)

	ksContext := make([]byte, 0, 1+len(pskIDHash)+len(infoHash))
	ksContext = append(ksContext, mode)
	ksContext = append(ksContext, pskIDHash...)
	ksContext = append(ksContext, infoHash...)

	secret := labeledExtract(sid, sharedSecret, []byte("secret"), nil)

	nk := aead.keySize()
	nn := aead.nonceSize()
	if nk == 0 || nn == 0 {
		return nil, nil, fmt.Errorf("unsupported AEAD 0x%04x", uint16(aead))
	}

	key = labeledExpand(sid, secret, []byte("key"), ksContext, nk)
	baseNonce = labeledExpand(sid, secret, []byte("base_nonce"), ksContext, nn)

	return key, baseNonce, nil
}

// labeledExtract per RFC 9180, Section 4:
//
//	LabeledExtract(salt, label, ikm) =
//	  Extract(salt, concat("HPKE-v1", suite_id, label, ikm))
func labeledExtract(sid, salt, label, ikm []byte) []byte {
	labeled := buildLabeledIKM(sid, label, ikm)
	return hkdfExtract(salt, labeled)
}

// labeledExpand per RFC 9180, Section 4:
//
//	LabeledExpand(prk, label, info, L) =
//	  Expand(prk, concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info), L)
func labeledExpand(sid, prk, label, info []byte, length int) []byte {
	labeledInfo := buildLabeledInfo(sid, label, info, length)
	return hkdfExpand(prk, labeledInfo, length)
}

func buildLabeledIKM(sid, label, ikm []byte) []byte {
	hpkeV1 := []byte("HPKE-v1")
	buf := make([]byte, 0, len(hpkeV1)+len(sid)+len(label)+len(ikm))
	buf = append(buf, hpkeV1...)
	buf = append(buf, sid...)
	buf = append(buf, label...)
	buf = append(buf, ikm...)
	return buf
}

func buildLabeledInfo(sid, label, info []byte, length int) []byte {
	hpkeV1 := []byte("HPKE-v1")
	buf := make([]byte, 0, 2+len(hpkeV1)+len(sid)+len(label)+len(info))
	buf = append(buf, byte(length>>8), byte(length))
	buf = append(buf, hpkeV1...)
	buf = append(buf, sid...)
	buf = append(buf, label...)
	buf = append(buf, info...)
	return buf
}

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, extractSize)
	}
	return hkdf.Extract(crypto.SHA512.New, ikm, salt)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	r := hkdf.Expand(crypto.SHA512.New, prk, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hpke: HKDF-Expand failed: " + err.Error())
	}
	return out
}
