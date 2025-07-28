package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"impersonator/fae"
)

func main() {
	fingerprintPath := flag.String("fingerprint", "fingerprint.json", "Path to the fingerprint file")
	url := flag.String("url", "jsonplaceholder.typicode.com/todos/1", "URL to request")
	timeout := flag.Duration("timeout", 10*time.Second, "Request timeout")
	flag.Parse()

	// Create a new context with the specified fingerprint
	faeCtx, err := fae.NewFaeContext(*fingerprintPath)
	if err != nil {
		log.Fatalf("Failed to create FAE context: %v", err)
	}
	defer faeCtx.Close()

	// Create a request context with a timeout
	reqCtx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Perform the GET request
	log.Printf("Making GET request to %s", *url)
	err, response := faeCtx.Get(reqCtx, *url)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(response)

	log.Println("Request successful")
}
