// Package httpts provides an HTTP server that runs on a Tailscale tailnet.
//
// Every http.Request context served by this package has httpts.Who attached
// to it, telling you who is calling.
package httpts

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"tailscale.com/client/tailscale"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

// Server is a drop-in for http.Server that serves a Handler on a tailnet.
type Server struct {
	Handler http.Handler

	ts      *tsnet.Server
	httpsrv *http.Server
	lc      *tailscale.LocalClient
}

// Who is attached to every http.Request context naming the HTTP client.
type Who struct {
	LoginName string
	PeerCap   tailcfg.PeerCapMap
}

func (w Who) equal(other Who) bool {
	return w.LoginName == other.LoginName &&
		maps.EqualFunc(w.PeerCap, other.PeerCap, func(a, b []tailcfg.RawMessage) bool {
			return slices.Equal(a, b)
		})
}

var whoCtxKey = struct{}{}

func WhoFromCtx(ctx context.Context) *Who {
	who, ok := ctx.Value(whoCtxKey).(*Who)
	if !ok {
		return nil
	}
	return who
}

func (s *Server) mkhttpsrv() {
	if s.httpsrv != nil {
		return
	}
	s.httpsrv = &http.Server{
		Handler: http.HandlerFunc(s.whoHandler),
	}
}

func (s *Server) whoHandler(w http.ResponseWriter, r *http.Request) {
	whoResp, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		http.Error(w, "httpts: "+err.Error(), http.StatusUnauthorized)
		return
	}
	who := Who{
		LoginName: whoResp.UserProfile.LoginName,
		PeerCap:   whoResp.CapMap,
	}
	r = r.WithContext(context.WithValue(r.Context(), whoCtxKey, &who))
	s.Handler.ServeHTTP(w, r)
}

// Serve serves :443 and a :80 redirect on a tailnet.
func (s *Server) Serve(tsHostname string) error {
	s.mkhttpsrv()
	confDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("httpsts: %w", err)
	}

	s.ts = &tsnet.Server{
		Dir:      filepath.Join(confDir, "httpts-"+tsHostname),
		Hostname: tsHostname,
	}
	defer s.ts.Close()

	ln, err := s.ts.ListenTLS("tcp", ":443")
	if err != nil {
		return fmt.Errorf("httpsts: %w", err)
	}
	lc, err := s.ts.LocalClient()
	if err != nil {
		return fmt.Errorf("httpsts: %w", err)
	}
	s.lc = lc
	if status, err := lc.Status(context.Background()); err != nil {
		return fmt.Errorf("httpsts: %w", err)
	} else {
		log.Printf("Running: https://%s/\n", strings.TrimSuffix(status.Self.DNSName, "."))
	}

	ln80, err := s.ts.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("httpsts: %w", err)
	}
	srv80 := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + r.Host + r.URL.Path
		if len(r.URL.RawQuery) > 0 {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})}
	go func() {
		err := srv80.Serve(ln80)
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
		panic(err)
	}()

	s.httpsrv.RegisterOnShutdown(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // shut down immediately
		srv80.Shutdown(ctx)
	})
	err = s.httpsrv.Serve(ln)
	s.lc = nil
	return err
}

func (s *Server) RegisterOnShutdown(f func()) {
	s.mkhttpsrv()
	s.httpsrv.RegisterOnShutdown(f)
}

// Shutdown shuts down the HTTP server and Tailscale client.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.httpsrv.Shutdown(ctx)
	err2 := s.ts.Close()
	if err == nil {
		err = err2
	}
	return err
}
