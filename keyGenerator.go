package Project

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// PubKey represents a public key.
type PubKey []byte

// PrivKey represents a private key.
type PrivKey []byte

/*GenerateKeyPair generates a public and private key pair using the provided
random source and elliptic curve. If the random source is nil, crypto/rand.Reader
is used. If the elliptic curve is nil, elliptic.P384() is used.

publicKey, privateKey := ec_ring_signature.GenerateKeyPair(nil, nil)
*/

func GenerateKeyPair(rand io.Reader, elepticCurve elliptic.Curve) (PubKey, PrivKey) {
	if rand == nil {
		rand = crand.Reader
	}
	if elepticCurve == nil {
		elepticCurve = elliptic.P384()
	}
	privat, x, y, err := elliptic.GenerateKey(elepticCurve, rand)
	if err != nil {
		panic(fmt.Sprintf("Не вдалось сгенерувати ключі: %s", err.Error()))
	}
	public := elliptic.Marshal(elepticCurve, x, y)
	return PubKey(public), PrivKey(privat)
}

/*
ConfigKey converts a key between different formats. It supports
converting between PubKey, PrivKey, []byte and string types.

	encodedPrivatKey, err := ec_ring_signature.ConfigKey(Privatkey)
*/
func ConfigKey(key interface{}) (interface{}, error) {
	switch t := key.(type) {
	case PubKey:
		return base64.StdEncoding.EncodeToString([]byte(t)), nil
	case PrivKey:
		return base64.StdEncoding.EncodeToString([]byte(t)), nil
	case []byte:
		return base64.StdEncoding.EncodeToString(t), nil
	case string:
		decoded, err := base64.StdEncoding.DecodeString(t)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}
