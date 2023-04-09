package Project

import (
	"crypto/elliptic"
	"fmt"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	fmt.Println("Running TestGenerateKeyPair...")
	pubKey, privKey := GenerateKeyPair(nil, nil)
	if len(pubKey) == 0 || len(privKey) == 0 {
		t.Error("Failed to generate keys")
	} else {
		fmt.Println("TestGenerateKeyPair passed")
	}
}

func TestConfigKey(t *testing.T) {
	fmt.Println("Running TestConfigKey...")
	pubKey, privKey := GenerateKeyPair(nil, elliptic.P256())
	pubKeyStr, err := ConfigKey(pubKey)
	if err != nil {
		t.Error(err)
	}
	if _, ok := pubKeyStr.(string); !ok {
		t.Error("Expected type string")
	}

	privKeyStr, err := ConfigKey(privKey)
	if err != nil {
		t.Error(err)
	}
	if _, ok := privKeyStr.(string); !ok {
		t.Error("Expected type string")
	}

	pubKeyBytes, err := ConfigKey(pubKeyStr)
	if err != nil {
		t.Error(err)
	}
	if _, ok := pubKeyBytes.([]byte); !ok {
		t.Error("Expected type []byte")
	}

	privKeyBytes, err := ConfigKey(privKeyStr)
	if err != nil {
		t.Error(err)
	}
	if _, ok := privKeyBytes.([]byte); !ok {
		t.Error("Expected type []byte")
	} else {
		fmt.Println("TestConfigKey passed")
	}
}

func TestSign(t *testing.T) {
	fmt.Println("Running TestSign...")
	ringKeys := make([]PubKey, 3)
	privKeys := make([]PrivKey, 3)
	for i := range ringKeys {
		ringKeys[i], privKeys[i] = GenerateKeyPair(nil, nil)
	}
	message := []byte("test message")
	signature, err := privKeys[0].Sign(nil, message, ringKeys, 0)
	if err != nil {
		t.Error(err)
	}
	if signature == nil {
		t.Error("Failed to generate signature")
	} else {
		fmt.Println("TestSign passed")
	}
}
func TestVerify(t *testing.T) {
	fmt.Println("Running TestVerify...")
	ringKeys := make([]PubKey, 3)
	privKeys := make([]PrivKey, 3)
	for i := range ringKeys {
		ringKeys[i], privKeys[i] = GenerateKeyPair(nil, nil)
	}
	message := []byte("test message")
	signature, err := privKeys[0].Sign(nil, message, ringKeys, 0)
	if err != nil {
		t.Error(err)
	}
	if !signature.Verify(message) {
		t.Error("Failed to verify signature")
	} else {
		fmt.Println("TestVerify passed")
	}
}
