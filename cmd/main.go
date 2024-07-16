package main

import auth "github.com/more-than-code/identity-provider"

func main() {
	port := 8003

	auth.NewServer(port)
}
