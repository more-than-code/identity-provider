package helper

import (
	"context"
	"fmt"
	"log"

	firebase "firebase.google.com/go/v4"
	"google.golang.org/api/idtoken"
)

func GetGoogleUserId(token string) (string, error) {

	// const googleClientId = "380364757130-f0pt75fsun8sk4p3l97sk5viqf94r1ak.apps.googleusercontent.com"
	const googleClientId = "321140371142-92pe1ullq3tsg1vnf5k97j2u99h7a3n6.apps.googleusercontent.com"

	payload, err := idtoken.Validate(context.Background(), token, googleClientId)
	if err != nil {
		return "", err
	}

	fmt.Print(payload.Claims)

	return payload.Subject, nil
}

func VerifyIdToken(ctx context.Context, idToken string) error {
	app, err := firebase.NewApp(ctx, nil)

	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	client, err := app.Auth(ctx)
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	token, err := client.VerifyIDToken(ctx, idToken)
	if err != nil {
		log.Fatalf("error verifying ID token: %v\n", err)
	}

	log.Printf("Verified ID token: %v\n", token)

	return nil
}
