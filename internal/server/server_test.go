package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoopbackOnly(t *testing.T) {
	for _, a := range []string{"0.0.0.0:8080", "[::]:8080", "localhost:8080", "example.com:80"} {
		if ValidateAddress(a) == nil {
			t.Fatal(a)
		}
	}
	for _, a := range []string{"127.0.0.1:8080", "[::1]:8080"} {
		if e := ValidateAddress(a); e != nil {
			t.Fatal(e)
		}
	}
}
func TestHandlerSecurity(t *testing.T) {
	h := Handler("127.0.0.1:8080", []byte("dashboard"), []byte("{}"))
	for _, tt := range []struct {
		method, path, host, origin string
		want                       int
	}{{"GET", "/", "127.0.0.1:8080", "", 200}, {"GET", "/results.json", "127.0.0.1:8080", "", 200}, {"HEAD", "/", "127.0.0.1:8080", "", 200}, {"POST", "/", "127.0.0.1:8080", "", 405}, {"GET", "/../../etc/passwd", "127.0.0.1:8080", "", 404}, {"GET", "/", "evil.example", "", 403}, {"GET", "/", "127.0.0.1:8080", "https://evil.example", 403}} {
		r := httptest.NewRequest(tt.method, tt.path, nil)
		r.Host = tt.host
		if tt.origin != "" {
			r.Header.Set("Origin", tt.origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tt.want {
			t.Fatalf("%+v got %d", tt, w.Code)
		}
		if tt.method == http.MethodHead && w.Body.Len() != 0 {
			t.Fatal("HEAD body")
		}
	}
}
