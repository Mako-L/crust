package mcpgateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckOrigin(t *testing.T) {
	tests := []struct {
		name         string
		origin       string
		referer      string
		secFetchSite string
		wantErr      bool
	}{
		// --- ALLOW: non-browser clients ---
		{name: "no headers (SDK/curl)", wantErr: false},

		// --- ALLOW: localhost origins ---
		{name: "localhost", origin: "http://localhost:6277", wantErr: false},
		{name: "localhost no port", origin: "http://localhost", wantErr: false},
		{name: "127.0.0.1", origin: "http://127.0.0.1:6277", wantErr: false},
		{name: "127.0.0.1 no port", origin: "http://127.0.0.1", wantErr: false},
		{name: "127.255.255.255", origin: "http://127.255.255.255:9090", wantErr: false},
		{name: "ipv6 loopback", origin: "http://[::1]:6277", wantErr: false},
		{name: "ipv6 loopback no port", origin: "http://[::1]", wantErr: false},
		{name: "0.0.0.0", origin: "http://0.0.0.0:6277", wantErr: false},

		// --- ALLOW: safe Sec-Fetch-Site values ---
		{name: "same-origin", origin: "http://localhost:6277", secFetchSite: "same-origin", wantErr: false},
		{name: "same-site", origin: "http://localhost:6277", secFetchSite: "same-site", wantErr: false},
		{name: "none (user-navigated)", secFetchSite: "none", wantErr: false},

		// --- BLOCK: cross-site browser CSRF ---
		{name: "cross-origin evil.com", origin: "https://evil.com", wantErr: true},
		{name: "cross-origin with path", origin: "https://attacker.io", wantErr: true},
		{name: "cross-site sec-fetch", origin: "https://evil.com", secFetchSite: "cross-site", wantErr: true},
		{name: "cross-site sec-fetch only", secFetchSite: "cross-site", wantErr: true},

		// --- BLOCK: DNS rebinding ---
		{name: "nip.io rebinding", origin: "http://127.0.0.1.nip.io:6277", wantErr: true},
		{name: "sslip.io rebinding", origin: "http://127.0.0.1.sslip.io:6277", wantErr: true},
		{name: "xip.io rebinding", origin: "http://10.0.0.1.xip.io:6277", wantErr: true},
		{name: "lvh.me rebinding", origin: "http://lvh.me:6277", wantErr: true},
		{name: "localtest.me rebinding", origin: "http://localtest.me:6277", wantErr: true},
		{name: "vcap.me rebinding", origin: "http://vcap.me:6277", wantErr: true},
		{name: "lacolhost.com rebinding", origin: "http://lacolhost.com:6277", wantErr: true},

		// --- BLOCK: null origin ---
		{name: "null origin (sandboxed iframe)", origin: "null", wantErr: true},

		// --- BLOCK: Referer fallback ---
		{name: "referer cross-origin", referer: "https://evil.com/exploit.html", wantErr: true},

		// --- ALLOW: Referer localhost ---
		{name: "referer localhost", referer: "http://localhost:6277/inspect", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			if tt.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.secFetchSite)
			}

			err := checkOrigin(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkOrigin() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
