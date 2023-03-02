package main

import auth "github.com/joe-and-his-friends/mo-service-auth"

func main() {
	port := 8003

	auth.NewServer(port)
}
