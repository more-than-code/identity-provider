package main

import auth "mo-service"

func main() {
	port := 8003

	auth.NewServer(port)
}
