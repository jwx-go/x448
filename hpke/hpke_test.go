package hpke_test

import (
	"testing"

	"github.com/jwx-go/x448/v4/dhkem"
	"github.com/jwx-go/x448/v4/hpke"
	"github.com/stretchr/testify/require"
)

func TestSealOpen_AES256GCM(t *testing.T) {
	testSealOpen(t, hpke.AES256GCM)
}

func TestSealOpen_ChaCha20Poly1305(t *testing.T) {
	testSealOpen(t, hpke.ChaCha20Poly1305)
}

func testSealOpen(t *testing.T, aead hpke.AEAD) {
	t.Helper()

	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	info := []byte("test info")
	aad := []byte("test aad")
	plaintext := []byte("Hello, HPKE X448!")

	enc, ciphertext, err := hpke.Seal(skR.PublicKey(), aead, info, aad, plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, enc)
	require.NotEmpty(t, ciphertext)

	opened, err := hpke.Open(skR, aead, enc, info, aad, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
}

func TestSealOpen_EmptyPlaintext(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	enc, ciphertext, err := hpke.Seal(skR.PublicKey(), hpke.AES256GCM, nil, nil, nil)
	require.NoError(t, err)

	opened, err := hpke.Open(skR, hpke.AES256GCM, enc, nil, nil, ciphertext)
	require.NoError(t, err)
	require.Empty(t, opened)
}

func TestSealOpen_NilInfo(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("no info")

	enc, ciphertext, err := hpke.Seal(skR.PublicKey(), hpke.AES256GCM, nil, nil, plaintext)
	require.NoError(t, err)

	opened, err := hpke.Open(skR, hpke.AES256GCM, enc, nil, nil, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
}

func TestOpen_WrongKey(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	skWrong, err := dhkem.GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("secret")
	enc, ciphertext, err := hpke.Seal(skR.PublicKey(), hpke.AES256GCM, nil, nil, plaintext)
	require.NoError(t, err)

	_, err = hpke.Open(skWrong, hpke.AES256GCM, enc, nil, nil, ciphertext)
	require.Error(t, err)
}

func TestOpen_WrongAAD(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("secret")
	enc, ciphertext, err := hpke.Seal(skR.PublicKey(), hpke.AES256GCM, nil, []byte("aad1"), plaintext)
	require.NoError(t, err)

	_, err = hpke.Open(skR, hpke.AES256GCM, enc, nil, []byte("aad2"), ciphertext)
	require.Error(t, err)
}

func TestOpen_WrongInfo(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("secret")
	enc, ciphertext, err := hpke.Seal(skR.PublicKey(), hpke.AES256GCM, []byte("info1"), nil, plaintext)
	require.NoError(t, err)

	_, err = hpke.Open(skR, hpke.AES256GCM, enc, []byte("info2"), nil, ciphertext)
	require.Error(t, err)
}

func TestOpen_WrongAEAD(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("secret")
	enc, ciphertext, err := hpke.Seal(skR.PublicKey(), hpke.AES256GCM, nil, nil, plaintext)
	require.NoError(t, err)

	_, err = hpke.Open(skR, hpke.ChaCha20Poly1305, enc, nil, nil, ciphertext)
	require.Error(t, err)
}

func TestOpen_TamperedCiphertext(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("secret")
	enc, ciphertext, err := hpke.Seal(skR.PublicKey(), hpke.AES256GCM, nil, nil, plaintext)
	require.NoError(t, err)

	ciphertext[0] ^= 0xFF
	_, err = hpke.Open(skR, hpke.AES256GCM, enc, nil, nil, ciphertext)
	require.Error(t, err)
}

func TestSealOpen_LargePayload(t *testing.T) {
	skR, err := dhkem.GenerateKey()
	require.NoError(t, err)

	plaintext := make([]byte, 64*1024)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	enc, ciphertext, err := hpke.Seal(skR.PublicKey(), hpke.AES256GCM, nil, nil, plaintext)
	require.NoError(t, err)

	opened, err := hpke.Open(skR, hpke.AES256GCM, enc, nil, nil, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
}

func FuzzSealOpen(f *testing.F) {
	f.Add([]byte("hello"), []byte("info"), []byte("aad"), uint8(0))
	f.Add([]byte{}, []byte{}, []byte{}, uint8(1))
	f.Add(make([]byte, 1024), []byte("x"), []byte("y"), uint8(0))

	f.Fuzz(func(t *testing.T, plaintext, info, aad []byte, aeadByte uint8) {
		var aead hpke.AEAD
		if aeadByte%2 == 0 {
			aead = hpke.AES256GCM
		} else {
			aead = hpke.ChaCha20Poly1305
		}

		skR, err := dhkem.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}

		enc, ciphertext, err := hpke.Seal(skR.PublicKey(), aead, info, aad, plaintext)
		if err != nil {
			t.Skip()
		}

		opened, err := hpke.Open(skR, aead, enc, info, aad, ciphertext)
		if err != nil {
			t.Fatalf("Open failed after Seal: %v", err)
		}

		if len(plaintext) == 0 && len(opened) == 0 {
			return
		}
		if string(plaintext) != string(opened) {
			t.Fatal("roundtrip mismatch")
		}
	})
}
