package x448

import (
	"crypto/rand"
	"testing"

	circlx448 "github.com/cloudflare/circl/dh/x448"
	"github.com/stretchr/testify/require"
)

// TestImportX448PrivateKeyRejectsInconsistentPubSeed pins the contract
// that importX448PrivateKey rejects a *PrivateKey whose pub field
// disagrees with KeyGen(seed). Construction via NewPrivateKey always
// satisfies the invariant; this test simulates a hand-assembled
// PrivateKey reaching the importer (the only ways to produce one are
// via unsafe pointer arithmetic, cgo, or a same-package wrapper —
// the test lives in package x448 to access the unexported fields
// directly without unsafe). The check defends against such values
// being imported into a JWK and used for thumbprint computation or
// further export before the inconsistency would surface on roundtrip.
func TestImportX448PrivateKeyRejectsInconsistentPubSeed(t *testing.T) {
	var seed circlx448.Key
	_, err := rand.Read(seed[:])
	require.NoError(t, err)

	t.Run("matching pub passes (control)", func(t *testing.T) {
		sk := NewPrivateKey(seed)
		_, err := importX448PrivateKey(sk)
		require.NoError(t, err, "consistent PrivateKey must import cleanly")
	})

	t.Run("mismatched pub is rejected", func(t *testing.T) {
		sk := &PrivateKey{seed: seed}
		// Set pub to something other than KeyGen(seed). Use the
		// next-byte-flipped variant of the correct pub so the
		// values are the right shape and length — only the value is
		// inconsistent.
		var correctPub circlx448.Key
		circlx448.KeyGen(&correctPub, &seed)
		sk.pub = correctPub
		sk.pub[0] ^= 0xff // flip a bit

		_, err := importX448PrivateKey(sk)
		require.Error(t, err, "mismatched pub must be rejected")
		require.Contains(t, err.Error(), "does not match",
			"error must name the consistency violation")
	})
}
