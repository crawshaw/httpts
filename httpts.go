// Package httpts provides an HTTP server that runs on a Tailscale tailnet.
//
// Every http.Request context served by this package has httpts.Who attached
// to it, telling you who is calling.
package httpts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/crawshaw/httpts/internal/tsnet"
	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// Server is a drop-in for http.Server that serves a Handler on a tailnet.
type Server struct {
	Handler http.Handler
	// InsecureLocalPortOnly, if non-zero, means that no tsnet server is started
	// and instead the server listens over http:// on the specified 127.0.0.1 port.
	InsecureLocalPortOnly int
	// StateStore, if non-nil, is used to store state for the tailscale client.
	StateStore ipn.StateStore

	AdvertiseTags []string

	// OauthClientSecret is used to authenticate the node if it is not already.
	// Create one at https://login.tailscale.com/admin/settings/oauth.
	// The client must be created with a tag that matches AdvertiseTags.
	// Note that the client secret must start with `tskey-client-`.
	OauthClientSecret string

	ts      *tsnet.Server
	httpsrv *http.Server
	lc      *tailscale.LocalClient

	ctx       context.Context
	ctxCancel func()

	started struct {
		mu sync.Mutex
		ch chan struct{} // closed when tsnet is serving, access via startedCh
	}
}

func (s *Server) startedCh() chan struct{} {
	s.started.mu.Lock()
	defer s.started.mu.Unlock()
	if s.started.ch == nil {
		s.started.ch = make(chan struct{})
	}
	return s.started.ch
}

// Who is attached to every http.Request context naming the HTTP client.
type Who struct {
	LoginName string
	PeerCap   tailcfg.PeerCapMap
}

type whoCtxKeyType struct{}

var whoCtxKey = whoCtxKeyType{}

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

// Dial dials the address on the tailnet.
func (s *Server) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if s.InsecureLocalPortOnly != 0 {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, address)
	}
	select {
	case <-s.startedCh():
		return s.ts.Dial(ctx, network, address)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Serve serves :443 and a :80 redirect on a tailnet.
func (s *Server) Serve(tsHostname string) error {
	s.mkhttpsrv()
	if s.InsecureLocalPortOnly != 0 {
		s.httpsrv.Addr = fmt.Sprintf("127.0.0.1:%d", s.InsecureLocalPortOnly)
		log.Printf("Serving: http://%s", s.httpsrv.Addr)
		return s.httpsrv.ListenAndServe()
	}

	s.ts = &tsnet.Server{
		Store:         s.StateStore,
		Hostname:      tsHostname,
		AdvertiseTags: s.AdvertiseTags,
	}
	defer s.ts.Close()

	// If this is the first time loading this server, create an auth key.
	initialLoad := false
	if s.StateStore != nil {
		if _, err := s.StateStore.ReadState(ipn.MachineKeyStateKey); errors.Is(err, ipn.ErrStateNotExist) {
			initialLoad = true
		}
	} else {
		confDir, err := os.UserConfigDir()
		if err != nil {
			return fmt.Errorf("httpts: %w", err)
		}
		s.ts.Dir = filepath.Join(confDir, "httpts-"+tsHostname)
		if _, err := os.Stat(s.ts.Dir); os.IsNotExist(err) {
			initialLoad = true
		}
	}
	if initialLoad && s.OauthClientSecret != "" {
		var err error
		s.ts.AuthKey, err = s.createAuthKey(context.Background())
		if err != nil {
			return fmt.Errorf("httpts: create auth key: %w", err)
		}
	}

	// Call Up explicitly with a context that is canceled on Shutdown
	// so we don't get stuck in ListenTLS on Shutdown.
	if _, err := s.ts.Up(s.ctx); err != nil {
		return fmt.Errorf("httpts.up: %w", err)
	}
	close(s.startedCh())
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

func tsClientConfig(clientSecret string) (*clientcredentials.Config, error) {
	oauthConfig := &clientcredentials.Config{
		ClientSecret: clientSecret,
		TokenURL:     "https://api.tailscale.com/api/v2/oauth/token",
	}
	if s := strings.TrimPrefix(oauthConfig.ClientSecret, "tskey-client-"); s == oauthConfig.ClientSecret {
		return nil, fmt.Errorf("OauthClientSecret must start with `tskey-client-`")
	} else {
		oauthConfig.ClientID, _, _ = strings.Cut(s, "-")
	}
	return oauthConfig, nil
}

func checkTSClientConfig(ctx context.Context, oauthConfig *clientcredentials.Config) error {
	tsClient := oauthConfig.Client(ctx)
	resp, err := tsClient.Get("https://api.tailscale.com/api/v2/tailnet/-/devices")
	if err != nil {
		return fmt.Errorf("oauth client failure: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("oauth client failure: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("basic device list failed: %s", body)
	}
	return nil
}

func (s *Server) createAuthKey(ctx context.Context) (string, error) {
	oauthCfg, err := tsClientConfig(s.OauthClientSecret)
	if err != nil {
		return "", err
	}
	if err := checkTSClientConfig(s.ctx, oauthCfg); err != nil {
		return "", err
	}

	tailscale.I_Acknowledge_This_API_Is_Unstable = true
	tsClient := tailscale.NewClient("-", nil)
	tsClient.HTTPClient = oauthCfg.Client(ctx)

	caps := tailscale.KeyCapabilities{
		Devices: tailscale.KeyDeviceCapabilities{
			Create: tailscale.KeyDeviceCreateCapabilities{
				Reusable:      false,
				Ephemeral:     false, // TODO export
				Preauthorized: true,  // false, // TODO export
				Tags:          s.AdvertiseTags,
			},
		},
	}
	authkey, _, err := tsClient.CreateKey(ctx, caps)
	if err != nil {
		return "", err
	}
	return authkey, nil
}
