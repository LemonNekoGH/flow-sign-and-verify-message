package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/onflow/flow-go-sdk"
	flowGrpc "github.com/onflow/flow-go-sdk/access/grpc"
	"github.com/onflow/flow-go/crypto/hash"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	ctx       context.Context
	flowCli   *flowGrpc.Client
	jwtSecret = []byte("S E C R E T")
)

type FlowInfo struct {
	Address string // user address
}

type TokenClaims struct {
	jwt.StandardClaims
	Info FlowInfo
}

// LoginRequest
type LoginRequest struct {
	Address   string `form:"address"`
	Signature string `form:"signature"`
	Message   string `form:"message"`
}

func (b LoginRequest) IsValid() bool {
	return strings.TrimSpace(b.Address) != "" && strings.TrimSpace(b.Signature) != ""
}

// 初始化 Flow 客户端
func initFlow() {
	var err error
	flowCli, err = flowGrpc.NewClient(flowGrpc.EmulatorHost, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
func verifySignature(message, address, signature string) bool {
	// get account
	account, err := flowCli.GetAccount(ctx, flow.HexToAddress(address))
	if err != nil {
		fmt.Printf("get account error, err: %s\n", err.Error())
		return false
	}
	// should not decode message string, should use hex message string.
	fmt.Printf("message: %s, sig: %s\n", message, signature)
	// decode signature, reference: https://github.com/onflow/flow-cli/blob/master/internal/signatures/verify.go#L64
	decodedSignature, err := hex.DecodeString(signature)
	if err != nil {
		fmt.Printf("signature decode error, err: %s\n", err.Error())
		return false
	}
	// try verify
	for _, key := range account.Keys {
		// revoked key cannot use to send transaction
		if key.Revoked {
			continue
		}
		ok, err := key.PublicKey.Verify(decodedSignature, []byte(message), getHasher(key.HashAlgo))
		if err != nil {
			fmt.Printf("verify failed, err: %s\n", err.Error())
			continue
		}
		if ok {
			return ok
		}
		fmt.Printf("verify failed. key index: %d, key: %s\n", key.Index, key.PublicKey.String())
	}
	return false
}

func postLogin(ctx *gin.Context) {
	// get body
	reqBody := LoginRequest{}
	if err := ctx.Bind(&reqBody); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"code":    40001, // bind failed
			"message": "request body format error",
		})
		return
	}
	if !verifySignature(reqBody.Message, reqBody.Address, reqBody.Signature) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"code":    40002, // signature verify failed
			"message": "signature verify failed",
		})
		return
	}
	// generate jwt
	issuedTime := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "https://blog.lemonneko.moe",
			IssuedAt:  issuedTime.Unix(),
			NotBefore: issuedTime.Unix(),
			ExpiresAt: issuedTime.Add(2 * time.Minute).Unix(), // expires after 2 minutes, for test
		},
		Info: FlowInfo{
			Address: reqBody.Address,
		},
	})
	// sign
	signedToken, _ := token.SignedString(jwtSecret)
	ctx.JSON(http.StatusOK, gin.H{
		"data": signedToken,
		"code": 0,
	})
}

// requireLogin.
// a middleware reject user when they not logged in.
// it will set FLOW_USER context key when pass.
func requireLogin(ctx *gin.Context) {
	// get token from http header
	tokenHeader := ctx.GetHeader("Authorization")
	token := strings.Fields(tokenHeader)[1]
	// verify token
	parsedToken, err := jwt.ParseWithClaims(token, TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected token signing method")
		}
		return jwtSecret, nil
	})
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"code":    40101, // parse error
			"message": "claims type error",
		})
		return
	}
	// check expires time
	err = parsedToken.Claims.Valid()
	if err != nil {
		validationErr := err.(jwt.ValidationError)
		// check expires error
		if validationErr.Is(jwt.ErrTokenExpired) {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    40102, // token expired
				"message": "token expired",
			})
			return
		}
	}

	// get payload
	claims, ok := parsedToken.Claims.(TokenClaims)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"code":    40101, // typecheck error
			"message": "unexpect type of claims",
		})
	}
	// set to context
	ctx.Set("FLOW_USER", claims.Info)

	ctx.Next()
}

// return user address
func getProfile(ctx *gin.Context) {
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

	// return address
	ctx.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"address": info.Address,
		},
	})
}

func allowAllOrigin(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", ctx.Request.Header.Get("Origin"))
	ctx.Header("Access-Control-Allow-Headers", "content-type")
	if ctx.Request.Method == http.MethodOptions {
		ctx.Status(http.StatusOK)
		return
	}
	ctx.Next()
}

func main() {
	ctx = context.Background()
	initFlow()

	r := gin.Default()
	r.Use(allowAllOrigin)
	r.POST("/login", postLogin)
	r.GET("/profile", requireLogin, getProfile)
	r.Run("0.0.0.0:3336")
}
