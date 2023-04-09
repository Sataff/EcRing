# EC Ring Signature Library

This library provides an implementation of elliptic curve ring signatures.

## Installation

To install the library, use the `go get` command:

go get https://github.com/Sataff/ec_ring_signature


## Usage

To use the library, import it into your Go code and use the provided functions to generate key pairs, sign messages and verify signatures.

Here is an example of how to use the library:

```go
package main

import (
	"fmt"

	"https://github.com/Sataff/ec_ring_signature"
)

func main() {
	// Generate a key pair
	pubKey, privKey := ec_ring_signature.GenerateKeyPair(nil, nil)

	// Create a ring of public keys
	ringKeys := []ec_ring_signature.PubKey{pubKey}

	// Sign a message
	message := []byte("test message")
	signature, err := privKey.Sign(nil, message, ringKeys, 0)
	if err != nil {
		panic(err)
	}

	// Verify the signature
	if signature.Verify(message) {
		fmt.Println("Signature is valid")
	} else {
		fmt.Println("Signature is invalid")
	}
}