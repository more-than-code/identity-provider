package helper

import (
	"context"
	"fmt"

	"google.golang.org/api/idtoken"
)

func GetGoogleUserId(token string) (string, error) {

	// const googleClientId = "380364757130-f0pt75fsun8sk4p3l97sk5viqf94r1ak.apps.googleusercontent.com"
	const googleClientId = "852240763326-u70m24kqprmt5kgt62dvc0i2856leq3g.apps.googleusercontent.com"

	payload, err := idtoken.Validate(context.Background(), token, googleClientId)
	if err != nil {
		return "", err
	}

	fmt.Print(payload.Claims)

	return payload.Subject, nil
}
