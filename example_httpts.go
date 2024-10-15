//go:build ignore
// +build ignore

// This example demos serving HTTP on your tailnet.
//
// To run entirely locally use:
//
//	go run ./example_httpts.go -devport 8080
//
// This is useful for local development on the bus.
// To run on a tailnet, drop the -devport flag:
//
//	go run ./example_httpts.go
//
// The first time, a tailscale login URL will be printed to put it on a tailnet.
// Then it will print out the full URL of this server.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/crawshaw/httpts"
)

func main() {
	devPort := flag.Int("devport", 0, "localhost port to run in dev mode, 0 to disable")
	flag.Parse()

	s := httpts.Server{
		Handler:               http.HandlerFunc(handler),
		InsecureLocalPortOnly: *devPort,
	}
	log.Fatal(s.Serve("httpts-example"))
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", httpts.WhoFromCtx(r.Context()).LoginName)
}
