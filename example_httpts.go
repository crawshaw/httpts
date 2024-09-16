//+build ignore

// This example demos serving HTTP on your tailnet.
//
// To run:
//	go run ./example_httpts.go
//
// The first time, a tailscale login URL will be printed to put it on a tailnet.
// Then it will print out the full URL of this server.
package main

import (
	"net/http"
	"fmt"
	"log"

	"github.com/crawshaw/httpts"
)

func main() {
	s := httpts.Server{
		Handler: http.HandlerFunc(handler),
	}
	log.Fatal(s.Serve("httpts-example"))
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", httpts.WhoFromCtx(r.Context()).LoginName)
}
