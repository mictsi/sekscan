// Package server serves only a generated dashboard and normalized JSON on loopback.
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

func ValidateAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("listen address must include host and port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("dashboard must bind to a loopback IP (127.0.0.1 or ::1)")
	}
	return nil
}
func Handler(address string, html, json []byte) http.Handler {
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
			http.Error(w, "read-only report", http.StatusMethodNotAllowed)
			return
		}
		var content []byte
		switch r.URL.Path {
		case "/", "/index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			content = html
		case "/results.json":
			w.Header().Set("Content-Type", "application/json")
			content = json
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(content)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(content)
		}
	})
}
func Serve(ctx context.Context, address string, html, json []byte, onReady func(string)) error {
	if e := ValidateAddress(address); e != nil {
		return e
	}
	listener, e := net.Listen("tcp", address)
	if e != nil {
		return e
	}
	actual := listener.Addr().String()
	srv := &http.Server{Handler: Handler(actual, html, json), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdown)
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
	return e
}
