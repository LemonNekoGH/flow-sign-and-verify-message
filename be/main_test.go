package main

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/onflow/flow-go-sdk/crypto"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	ctx = context.Background()
	initFlow()
	m.Run()
}

// signAMessage. helper func, return signature and message
func signAMessage(assert *assert.Assertions) (string, string) {
	privateKey, err := crypto.DecodePrivateKeyHex(crypto.ECDSA_P256, "030ad9fe06e584cdc8afe744c0012d0397a0805e133a5dacdf83b94a996a6972")
	assert.NoError(err)
	// message := fmt.Sprintf("Welcome to LemonNeko's blog. %d", time.Now().UnixMilli())
	message := "Welcome to LemonNeko's blog. 1662696806339"
	encodedMessage := hex.EncodeToString([]byte(message))
	sig, err := privateKey.Sign([]byte(encodedMessage), crypto.NewSHA3_256())
	assert.NoError(err)
	return sig.String(), encodedMessage
}

func TestVerifySignature(t *testing.T) {
	t.Run("address error", func(t *testing.T) {
		assert := assert.New(t)
		sig, msg := signAMessage(assert)
		assert.False(verifySignature([]string{sig}, []int{0}, msg, "", "0x00012456"))
	})
	t.Run("signature cannot decode", func(t *testing.T) {
		assert := assert.New(t)
		_, msg := signAMessage(assert)
		assert.False(verifySignature([]string{"1234567"}, []int{0}, msg, "", "0xf8d6e0586b0a20c7"))
	})
	t.Run("no error", func(t *testing.T) {
		assert := assert.New(t)
		sig, msg := signAMessage(assert)
		assert.False(verifySignature([]string{sig}, []int{0}, msg, "", "0xf8d6e0586b0a20c7"))
	})
}
