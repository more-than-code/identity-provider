package helper

import (
	"context"
	"fmt"
	"log"

	"github.com/Timothylock/go-signin-with-apple/apple"
	"github.com/kelseyhightower/envconfig"
)

type AppleAuthConfig struct {
	AppleAuthPrivateKey string `envconfig:"APPLE_AUTH_PRIVATE_KEY"`
}

func GetAppleUserId(authCode string) (string, error) {
	var cfg AppleAuthConfig
	err := envconfig.Process("", &cfg)
	if err != nil {
		log.Fatal(err)
	}

	clientId := "com.mohiguide.ios"
	keyId := "3V5G9SJLFF"
	teamId := "NW53JN42Q8"

	secret := cfg.AppleAuthPrivateKey

	secret, err = apple.GenerateClientSecret(secret, teamId, clientId, keyId)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	client := apple.New()

	vReq := apple.AppValidationTokenRequest{
		ClientID:     clientId,
		ClientSecret: secret,
		Code:         authCode,
	}

	var resp apple.ValidationResponse

	err = client.VerifyAppToken(context.Background(), vReq, &resp)

	if err != nil {
		fmt.Println(err)
		return "", nil
	}

	unique, err := apple.GetUniqueID(resp.IDToken)

	if err != nil {
		fmt.Println(err)
		return "", nil
	}

	return unique, nil
}
