// The tailweb command serves out the current directory to your tailnet.
//
// This is the tailscale equivalent of the classic python one-liner:
//
//	python -m http.server 8000
//
// Install tailweb with:
//
//	go install github.com/crawshaw/httpts/cmd/tailweb@latest
//
// then to serve the current directory, run:
//
//	tailweb
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/crawshaw/httpts"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: tailweb [dir]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	tsHostname := flag.String("hostname", hostname+"-tailweb", "hostname to use for the server")
	flag.Parse()

	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if args := flag.Args(); len(args) == 1 {
		dir = flag.Args()[0]
	} else if len(flag.Args()) > 1 {
		usage()
	}

	s := httpts.Server{Handler: http.FileServer(http.Dir(dir))}
	panic(s.Serve(*tsHostname))
}
