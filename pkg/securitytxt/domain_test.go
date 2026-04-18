package securitytxt

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBaseDomain(t *testing.T) {
	tests := map[string]string{
		"":                "",
		"www.example.com": "example.com",
		"foo.co.uk":       "foo.co.uk",
		"example.com.":    "example.com",
		"127.0.0.1":       "127.0.0.1",
	}

	for in, want := range tests {
		if got := baseDomain(in); got != want {
			t.Fatalf("baseDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGetBodyReturnsFinalURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/.well-known/security.txt", http.StatusFound)
		case "/.well-known/security.txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewDomainClient(NewConfig())
	if err != nil {
		t.Fatalf("NewDomainClient() error = %v", err)
	}

	_, finalURL, err := client.GetBody(server.URL + "/start")
	if err != nil {
		t.Fatalf("GetBody() error = %v", err)
	}

	want := server.URL + "/.well-known/security.txt"
	if finalURL != want {
		t.Fatalf("GetBody() final URL = %q, want %q", finalURL, want)
	}
}
