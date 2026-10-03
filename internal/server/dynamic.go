package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SecureHandler protects database-backed views with the same loopback/Host/origin boundary.
func SecureHandler(address string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if !strings.EqualFold(r.Host, address) {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			if e != nil || u.Scheme != "http" || !strings.EqualFold(u.Host, address) {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only dashboard", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func ServeDynamic(ctx context.Context, address string, next http.Handler, onReady func(string)) error {
	if e := ValidateAddress(address); e != nil {
		return e
	}
	listener, e := net.Listen("tcp", address)
	if e != nil {
		return e
	}
	actual := listener.Addr().String()
	srv := &http.Server{Handler: SecureHandler(actual, next), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(stop)
		case <-done:
		}
	}()
	if onReady != nil {
		onReady("http://" + actual)
	}
	e = srv.Serve(listener)
	if e == http.ErrServerClosed {
		return nil
	}
	if e != nil {
		return fmt.Errorf("dashboard server: %w", e)
	}
	return nil
}
