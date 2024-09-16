// The tailweb command serves out the current directory to your tailnet.
package main

import (
	"flag"
	"fmt"
	"log"
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
		log.Fatal(err)
	}
	tsHostname := flag.String("hostname", hostname+"-tailweb", "hostname to use for the server")
	flag.Parse()
	log.SetPrefix("tailweb: ")
	log.SetFlags(0)

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	if args := flag.Args(); len(args) == 1 {
		dir = flag.Args()[0]
	} else if len(flag.Args()) > 1 {
		usage()
	}

	s := httpts.Server{Handler: http.FileServer(http.Dir(dir))}
	log.Fatal(s.Serve(*tsHostname))
}
