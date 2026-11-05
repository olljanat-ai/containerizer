package main

import (
	"log"
	"os"

	"example.com/orders/internal/server"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	log.Fatal(server.Run(":" + port))
}
