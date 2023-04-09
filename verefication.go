package Project

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
)

/*
Verify verifies the ring signature for the provided message. It returns true
if the signature is valid and false otherwise.

signature.Verify(message)
*/
func (sig *Signature) Verify(message []byte) bool {
	if sig == nil || len(sig.ring) < 2 || len(sig.s) != len(sig.ring) || len(sig.e) == 0 {
		return false
	}
	curve := elliptic.P384()
	e := make([]byte, len(sig.e))
	copy(e, sig.e)
	for i := 0; i < len(sig.ring); i++ {
		x1, y1 := curve.ScalarBaseMult(sig.s[i])
		px, py := elliptic.Unmarshal(curve, sig.ring[i])
		x2, y2 := curve.ScalarMult(px, py, e)
		x, y := curve.Add(x1, y1, x2, y2)
		e = hash(append(message, elliptic.Marshal(curve, x, y)...))
	}
	return bytes.Equal(e, sig.e)
}

/*
hash calculates the SHA-256 hash of the provided data.

e = hash(append(message, elliptic.Marshal(curve, x, y)...))
*/
func hash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
