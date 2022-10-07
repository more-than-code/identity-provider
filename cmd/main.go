package main

import auth "mo-service-auth"

func main() {
	port := 8003

	auth.NewServer(port)
}
