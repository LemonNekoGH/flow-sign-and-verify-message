package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

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
	message := fmt.Sprintf("Welcome to LemonNeko's blog. %d", time.Now().UnixMilli())
	encodedMessage := hex.EncodeToString([]byte(message))
	sig, err := privateKey.Sign([]byte(encodedMessage), crypto.NewSHA3_256())
	assert.NoError(err)
	return sig.String(), encodedMessage
}

func TestVerifySignature(t *testing.T) {
	t.Run("address error", func(t *testing.T) {
		assert := assert.New(t)
		sig, msg := signAMessage(assert)
		assert.False(verifySignature(msg, "0x00012456", sig))
	})
	t.Run("signature cannot decode", func(t *testing.T) {
		assert := assert.New(t)
		_, msg := signAMessage(assert)
		assert.False(verifySignature(msg, "0xf8d6e0586b0a20c7", "1234567"))
	})
	t.Run("no error", func(t *testing.T) {
		assert := assert.New(t)
		sig, msg := signAMessage(assert)
		assert.True(verifySignature(msg, "0xf8d6e0586b0a20c7", strings.TrimPrefix(sig, "0x")))
	})
	t.Run("no error, from frontend", func(t *testing.T) {
		assert := assert.New(t)
		assert.True(verifySignature(
			"57656c636f6d6520746f204c656d6f6e4e656b6f277320626c6f672e2031363632363935343531323433",
			"0xf8d6e0586b0a20c7",
			"6b902a9c96277bdc62f76db5cc64fa50596d0b8889077df190daf680cb505e7208871ec30270b6705aa457b0340c099a88ce5d14feb8db7e5fdf02ea4af16e5b",
		))
	})
}
