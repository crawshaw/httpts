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
	// InsecureLocalPortOnly, if non-zero, means that no tsnet server is started
	// and instead the server listens over http:// on the specified 127.0.0.1 port.
	InsecureLocalPortOnly int

	ts      *tsnet.Server
	httpsrv *http.Server
	lc      *tailscale.LocalClient

	ctx       context.Context
	ctxCancel func()
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
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())
	s.httpsrv = &http.Server{
		Handler: http.HandlerFunc(s.whoHandler),
	}
}

func (s *Server) whoHandler(w http.ResponseWriter, r *http.Request) {
	var who Who
	if s.InsecureLocalPortOnly != 0 {
		who = Who{LoginName: "insecure-localhost"}
	} else {
		whoResp, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			http.Error(w, "httpts: "+err.Error(), http.StatusUnauthorized)
			return
		}
		who = Who{
			LoginName: whoResp.UserProfile.LoginName,
			PeerCap:   whoResp.CapMap,
		}
	}
	r = r.WithContext(context.WithValue(r.Context(), whoCtxKey, &who))
	s.Handler.ServeHTTP(w, r)
}

// Serve serves :443 and a :80 redirect on a tailnet.
func (s *Server) Serve(tsHostname string) error {
	s.mkhttpsrv()
	if s.InsecureLocalPortOnly != 0 {
		s.httpsrv.Addr = fmt.Sprintf("127.0.0.1:%d", s.InsecureLocalPortOnly)
		log.Printf("Serving: http://%s", s.httpsrv.Addr)
		return s.httpsrv.ListenAndServe()
	}

	confDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("httpts: %w", err)
	}

	s.ts = &tsnet.Server{
		Dir:      filepath.Join(confDir, "httpts-"+tsHostname),
		Hostname: tsHostname,
	}
	defer s.ts.Close()

	// Call Up explicitly with a context that is canceled on Shutdown
	// so we don't get stuck in ListenTLS on Shutdown.
	if _, err := s.ts.Up(s.ctx); err != nil {
		return fmt.Errorf("httpts: %w", err)
	}
	ln, err := s.ts.ListenTLS("tcp", ":443")
	if err != nil {
		return fmt.Errorf("httpts: %w", err)
	}
	lc, err := s.ts.LocalClient()
	if err != nil {
		return fmt.Errorf("httpts: %w", err)
	}
	s.lc = lc
	if status, err := lc.Status(context.Background()); err != nil {
		return fmt.Errorf("httpts: %w", err)
	} else {
		log.Printf("Serving: https://%s/\n", strings.TrimSuffix(status.Self.DNSName, "."))
	}

	ln80, err := s.ts.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("httpts: %w", err)
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

// Shutdown shuts down the HTTP server and Tailscale client.
func (s *Server) Shutdown(ctx context.Context) error {
	s.ctxCancel()
	var err, err2 error
	err = s.httpsrv.Shutdown(ctx)
	if s.ts != nil {
		err2 = s.ts.Close()
	}
	s.ts = nil
	if err == nil {
		err = err2
	}
	return err
}
