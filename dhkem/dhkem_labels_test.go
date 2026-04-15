package dhkem

import (
	"bytes"
	"testing"
)

// TestExtractAndExpandUsesRFC9180Labels pins the DHKEM ExtractAndExpand
// labels against the literal text of RFC 9180 Section 4.1:
//
//	eae_prk = LabeledExtract("", "eae_prk", dh)
//	shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
//
// Earlier versions of this package used "shared_key" / "secret" — locally
// consistent but non-interoperable with any other RFC 9180 implementation.
// The test cross-checks the production extractAndExpand against an inline
// reconstruction that uses the spec-correct labels. If the production
// labels diverge, the test fails.
func TestExtractAndExpandUsesRFC9180Labels(t *testing.T) {
	cases := []struct {
		name       string
		dh         []byte
		kemContext []byte
	}{
		{
			name:       "zero dh, zero context",
			dh:         make([]byte, Nsk),
			kemContext: make([]byte, Nenc+Npk),
		},
		{
			name:       "patterned dh, patterned context",
			dh:         patterned(Nsk, 0x11),
			kemContext: patterned(Nenc+Npk, 0x22),
		},
		{
			name:       "high-bit dh, high-bit context",
			dh:         patterned(Nsk, 0xff),
			kemContext: patterned(Nenc+Npk, 0xfe),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Spec-correct construction: "eae_prk" then "shared_secret".
			expectedPrk := labeledExtract([]byte("eae_prk"), tc.dh)
			expected := labeledExpand(expectedPrk, []byte("shared_secret"), tc.kemContext, Nsecret)

			actual := extractAndExpand(tc.dh, tc.kemContext)

			if !bytes.Equal(expected, actual) {
				t.Fatalf("extractAndExpand output diverges from RFC 9180 §4.1 labels\n  expected: %x\n  actual:   %x", expected, actual)
			}
		})
	}
}

// TestExtractAndExpandRejectsLegacyLabels guards against the specific
// regression of using "shared_key" / "secret" instead of the RFC 9180
// labels. If extractAndExpand were to use the legacy labels, this test
// would pass against the legacy reconstruction below — which is exactly
// what we want to detect and fail on.
func TestExtractAndExpandRejectsLegacyLabels(t *testing.T) {
	dh := patterned(Nsk, 0x55)
	kemContext := patterned(Nenc+Npk, 0xaa)

	// Reconstruct what the buggy implementation would have produced.
	legacyPrk := labeledExtract([]byte("shared_key"), dh)
	legacyOutput := labeledExpand(legacyPrk, []byte("secret"), kemContext, Nsecret)

	actual := extractAndExpand(dh, kemContext)

	if bytes.Equal(actual, legacyOutput) {
		t.Fatal("extractAndExpand still produces the pre-RFC-9180 output (labels are 'shared_key' / 'secret' instead of 'eae_prk' / 'shared_secret')")
	}
}

func patterned(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b ^ byte(i)
	}
	return out
}
