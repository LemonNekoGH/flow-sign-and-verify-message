package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LemonNekoGH/godence"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/onflow/cadence"
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
	Address    string   `form:"address"`
	Signatures []string `form:"signatures"`
	KeyIndices []int    `form:"keyIndices"`
	Message    string   `form:"message"`
}

func (b LoginRequest) IsValid() bool {
	return strings.TrimSpace(b.Address) != "" && len(b.Signatures) != 0 && len(b.KeyIndices) != 0 && strings.TrimSpace(b.Message) != ""
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
func verifySignature(signature []string, keys []int, message, tag, address string) (bool, error) {
	const script = `
pub fun main(
	address: Address,
	message: String,
	keyIndices: [Int],
	signatures: [String],
	domainSeparationTag: String,
): Bool {
	pre {
		keyIndices.length == signatures.length : "Key index list length does not match signature list length"
	}

	let account = getAccount(address)
	let messageBytes = message.decodeHex()

	var totalWeight: UFix64 = 0.0
	let seenKeyIndices: {Int: Bool} = {}

	var i = 0

	for keyIndex in keyIndices {

		let accountKey = account.keys.get(keyIndex: keyIndex) ?? panic("Key provided does not exist on account")
		let signature = signatures[i].decodeHex()

		// Ensure this key index has not already been seen

		if seenKeyIndices[accountKey.keyIndex] ?? false {
			return false
		}

		// Record the key index was seen

		seenKeyIndices[accountKey.keyIndex] = true

		// Ensure the key is not revoked

		if accountKey.isRevoked {
			return false
		}

		// Ensure the signature is valid

		if !accountKey.publicKey.verify(
			signature: signature,
			signedData: messageBytes,
			domainSeparationTag: domainSeparationTag,
			hashAlgorithm: accountKey.hashAlgorithm
		) {
			return false
		}

		totalWeight = totalWeight + accountKey.weight

		i = i + 1
	}
	
	return totalWeight >= 1000.0
}`
	cdcTag, _ := godence.ToCadence(tag)
	cdcMsg, _ := godence.ToCadence(message)
	cdcSig, _ := godence.ToCadence(signature)
	cdcKeys, _ := godence.ToCadence(keys)
	cdcAddr, _ := godence.ToCadence(godence.Address(address))
	// get account
	result, err := flowCli.ExecuteScriptAtLatestBlock(ctx, []byte(script), []cadence.Value{
		cdcAddr, cdcMsg, cdcKeys, cdcSig, cdcTag,
	})
	if err != nil {
		return false, err
	}
	r := false
	_ = godence.ToGo(result, &r)

	return r, nil
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
	ok, err := verifySignature(reqBody.Signatures, reqBody.KeyIndices, reqBody.Message, "FLOW-V0.0-user", reqBody.Address)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"code":    50001, // flow cli failed
			"message": "signature verify failed, please try again later",
		})
		return
	}
	if !ok {
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

	claims := &TokenClaims{}
	// verify token
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected token signing method")
		}
		return jwtSecret, nil
	})
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"code":    40101, // parse error
			"message": "claims type error: " + err.Error(),
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
	ctx.Header("Access-Control-Allow-Headers", "content-type, authorization")
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
