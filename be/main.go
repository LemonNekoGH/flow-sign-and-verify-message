package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/onflow/flow-go-sdk"
	flowGrpc "github.com/onflow/flow-go-sdk/access/grpc"
	"github.com/onflow/flow-go/crypto"
	"github.com/onflow/flow-go/crypto/hash"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	ctx             context.Context
	flowCli         *flowGrpc.Client
	messageToVerify = []byte("Welcome to LemonNeko's blog.")
)

type FlowInfo struct {
	Address string // user address
}

// 初始化 Flow 客户端
func initFlow() {
	var err error
	flowCli, err = flowGrpc.NewClient(flowGrpc.TestnetHost, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	err = flowCli.Ping(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Flow client init success.")
}

// return suitable hasher
func getHasher(algo hash.HashingAlgorithm) hash.Hasher {
	switch algo {
	case hash.SHA2_256:
		return hash.NewSHA2_256()
	case hash.SHA2_384:
		return hash.NewSHA2_384()
	case hash.SHA3_256:
		return hash.NewSHA3_256()
	case hash.SHA3_384:
		return hash.NewSHA3_384()
	case hash.Keccak_256:
		return hash.NewKeccak_256()
	}
	return nil
}

// require user address, and signature
func verifySignature(address string, signature string) bool {
	// get account
	account, err := flowCli.GetAccount(ctx, flow.HexToAddress(address))
	if err != nil {
		return false
	}
	// try verify
	for _, key := range account.Keys {
		// revoked key cannot use to send transaction
		if key.Revoked {
			continue
		}
		ok, err := key.PublicKey.Verify(crypto.Signature(signature), messageToVerify, getHasher(key.HashAlgo))
		if err != nil {
			fmt.Printf("verify failed, err: %s\n", err.Error())
			continue
		}
		if ok {
			return ok
		}
		fmt.Printf("verify failed.\n")
	}
	return false
}

func requireFlowSignature(ctx *gin.Context) {
	// get address and signature from http header
	address := ctx.GetHeader("X-User-Address")
	if strings.TrimSpace(address) == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "X-User-Address header not found",
		})
		return
	}
	signature := ctx.GetHeader("X-User-Signature")
	if strings.TrimSpace(signature) == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "X-User-Signature header not found",
		})
		return
	}
	// verify signature
	if !verifySignature(address, signature) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"code":    401,
			"message": "signature verify failed",
		})
		return
	}
	ctx.Next()
}

// return pong
func getPing(ctx *gin.Context) {
	// get flow user from context
	flowAccount, ok := ctx.Get("FLOW_USER")
	if !ok {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	// covert
	info, ok := flowAccount.(FlowInfo)
	if !ok {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// return pong with address
	ctx.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"message": "pong",
			"address": info.Address,
		},
	})
}

func main() {
	ctx = context.Background()
	initFlow()

	r := gin.Default()
	r.GET("/ping", requireFlowSignature, getPing)
	r.Run("0.0.0.0:3336")
}
