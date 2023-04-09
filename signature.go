package Project

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"errors"
	"io"
	"math/big"
)

/*
Signature represents a ring signature.
*/
type Signature struct {
	ring []PubKey
	e    []byte
	s    [][]byte
}

/*
Sign creates a ring signature for the provided message using the private key,
ring of public keys and signer index. The random source is used to generate
random values during the signing process. If the random source is nil,
crypto/rand.Reader is used.

signature, err := privKeys[0].Sign(nil, message, ringKeys, 0)
*/
func (pk PrivKey) Sign(
	rand io.Reader,
	message []byte,
	ringKeys []PubKey,
	signerIndex int,
) (*Signature, error) {
	if len(message) == 0 {
		return nil, errors.New("Ви повинні надати повідомлення для підпису")
	}
	if signerIndex < 0 || len(ringKeys) <= signerIndex {
		return nil, errors.New("Індекс підписанта повинен бути в кільці")
	}
	if len(ringKeys) < 2 {
		return nil, errors.New("Кільце замале: потрібно не менше двох учасників")
	}
	if rand == nil {
		rand = crand.Reader
	}
	es := make([][]byte, len(ringKeys))
	ss := make([][]byte, len(ringKeys))
	curve := elliptic.P384()
	r := len(ringKeys)
	k, err := randomParam(curve, rand)
	if err != nil {
		return nil, err
	}
	x, y := curve.ScalarBaseMult(k)
	es[(signerIndex+1)%r] = hash(append(message, elliptic.Marshal(curve, x, y)...))
	for i := (signerIndex + 1) % r; i != signerIndex; i = (i + 1) % r {
		s, err := randomParam(curve, rand)
		if err != nil {
			return nil, err
		}
		ss[i] = s
		x1, y1 := curve.ScalarBaseMult(ss[i])
		px, py := elliptic.Unmarshal(curve, ringKeys[i])
		x2, y2 := curve.ScalarMult(px, py, es[i])
		x, y = curve.Add(x1, y1, x2, y2)
		es[(i+1)%r] = hash(append(message, elliptic.Marshal(curve, x, y)...))
	}
	valK := new(big.Int).SetBytes(k)
	valE := new(big.Int).SetBytes(es[signerIndex])
	valX := new(big.Int).SetBytes(pk)
	valS := new(big.Int).Sub(valK, new(big.Int).Mul(valE, valX))
	if valS.Sign() == -1 {
		add := new(big.Int).Mul(valE, curve.Params().N)
		valS = valS.Add(valS, add)
		_, valS = new(big.Int).DivMod(valS, curve.Params().N, new(big.Int))
		if valS.Sign() == 0 {
			return nil, errors.New("не вдалося створити підпис")
		}
	}
	ss[signerIndex] = valS.Bytes()
	sig := &Signature{
		ring: ringKeys,
		e:    es[0],
		s:    ss,
	}
	return sig, nil
} /*
randomParam generates a random value using the provided elliptic curve and
random source. The random value is in the range [1, N-1], where N is the
order of the curve's base point.

s, err := randomParam(curve, rand)
*/
func randomParam(curve elliptic.Curve, rand io.Reader) ([]byte, error) {
	for {
		r, err := crand.Int(rand, curve.Params().N)
		if err != nil {
			return nil, err
		}
		if r.Sign() == 1 {
			return r.Bytes(), nil
		}
	}
}
