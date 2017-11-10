package httpproxy_test

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/http/httpproxy"
)

type proxyForURLTest struct {
	req string // URL to fetch; blank means "http://example.com"

	env      string // HTTP_PROXY
	httpsenv string // HTTPS_PROXY
	noenv    string // NO_PROXY

	want    string
	wanterr error
}

func (t proxyForURLTest) String() string {
	var buf bytes.Buffer
	space := func() {
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
	}
	if t.env != "" {
		fmt.Fprintf(&buf, "http_proxy=%q", t.env)
	}
	if t.httpsenv != "" {
		space()
		fmt.Fprintf(&buf, "https_proxy=%q", t.httpsenv)
	}
	if t.noenv != "" {
		space()
		fmt.Fprintf(&buf, "no_proxy=%q", t.noenv)
	}
	req := "http://example.com"
	if t.req != "" {
		req = t.req
	}
	space()
	fmt.Fprintf(&buf, "req=%q", req)
	return strings.TrimSpace(buf.String())
}

var proxyForURLTests = []proxyForURLTest{
	{env: "127.0.0.1:8080", want: "http://127.0.0.1:8080"},
	{env: "cache.corp.example.com:1234", want: "http://cache.corp.example.com:1234"},
	{env: "cache.corp.example.com", want: "http://cache.corp.example.com"},
	{env: "https://cache.corp.example.com", want: "https://cache.corp.example.com"},
	{env: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
	{env: "https://127.0.0.1:8080", want: "https://127.0.0.1:8080"},
	{env: "socks5://127.0.0.1", want: "socks5://127.0.0.1"},

	// Don't use secure for http
	{req: "http://insecure.tld/", env: "http.proxy.tld", httpsenv: "secure.proxy.tld", want: "http://http.proxy.tld"},
	// Use secure for https.
	{req: "https://secure.tld/", env: "http.proxy.tld", httpsenv: "secure.proxy.tld", want: "http://secure.proxy.tld"},
	{req: "https://secure.tld/", env: "http.proxy.tld", httpsenv: "https://secure.proxy.tld", want: "https://secure.proxy.tld"},

	{want: "<nil>"},

	{noenv: "example.com", req: "http://example.com/", env: "proxy", want: "<nil>"},
	{noenv: ".example.com", req: "http://example.com/", env: "proxy", want: "<nil>"},
	{noenv: "ample.com", req: "http://example.com/", env: "proxy", want: "http://proxy"},
	{noenv: "example.com", req: "http://foo.example.com/", env: "proxy", want: "<nil>"},
	{noenv: ".foo.com", req: "http://example.com/", env: "proxy", want: "http://proxy"},
}

func testProxyForURL(t *testing.T, tt proxyForURLTest, proxyForURL func(reqURL *url.URL) (*url.URL, error)) {
	t.Helper()
	reqURLStr := tt.req
	if reqURLStr == "" {
		reqURLStr = "http://example.com"
	}
	reqURL, err := url.Parse(reqURLStr)
	if err != nil {
		t.Errorf("invalid URL %q", reqURLStr)
		return
	}
	url, err := proxyForURL(reqURL)
	if g, e := fmt.Sprintf("%v", err), fmt.Sprintf("%v", tt.wanterr); g != e {
		t.Errorf("%v: got error = %q, want %q", tt, g, e)
		return
	}
	if got := fmt.Sprintf("%s", url); got != tt.want {
		t.Errorf("%v: got URL = %q, want %q", tt, url, tt.want)
	}
}

func TestConfig(t *testing.T) {
	for _, tt := range proxyForURLTests {
		testProxyForURL(t, tt, func(reqURL *url.URL) (*url.URL, error) {
			cfg := httpproxy.Config{
				HTTPProxy:  tt.env,
				HTTPSProxy: tt.httpsenv,
				NoProxy:    tt.noenv,
			}
			return cfg.ProxyForURL(reqURL)
		})
	}
}

func TestFromEnvironment(t *testing.T) {
	os.Setenv("HTTP_PROXY", "httpproxy")
	os.Setenv("HTTPS_PROXY", "httpsproxy")
	os.Setenv("NO_PROXY", "noproxy")
	got := httpproxy.FromEnvironment()
	want := httpproxy.Config{
		HTTPProxy:  "httpproxy",
		HTTPSProxy: "httpsproxy",
		NoProxy:    "noproxy",
	}
	if *got != want {
		t.Errorf("unexpected proxy config, got %#v want %#v", got, want)
	}
}

func TestFromEnvironmentLowerCase(t *testing.T) {
	os.Setenv("http_proxy", "httpproxy")
	os.Setenv("https_proxy", "httpsproxy")
	os.Setenv("no_proxy", "noproxy")
	got := httpproxy.FromEnvironment()
	want := httpproxy.Config{
		HTTPProxy:  "httpproxy",
		HTTPSProxy: "httpsproxy",
		NoProxy:    "noproxy",
	}
	if *got != want {
		t.Errorf("unexpected proxy config, got %#v want %#v", got, want)
	}
}

var UseProxyTests = []struct {
	host  string
	match bool
}{
	// Never proxy localhost:
	{"localhost", false},
	{"127.0.0.1", false},
	{"127.0.0.2", false},
	{"[::1]", false},
	{"[::2]", true}, // not a loopback address

	{"barbaz.net", false},     // match as .barbaz.net
	{"foobar.com", false},     // have a port but match
	{"foofoobar.com", true},   // not match as a part of foobar.com
	{"baz.com", true},         // not match as a part of barbaz.com
	{"localhost.net", true},   // not match as suffix of address
	{"local.localhost", true}, // not match as prefix as address
	{"barbarbaz.net", true},   // not match because NO_PROXY have a '.'
	{"www.foobar.com", false}, // match because NO_PROXY includes "foobar.com"
}

func TestUseProxy(t *testing.T) {
	cfg := &httpproxy.Config{
		NoProxy: "foobar.com, .barbaz.net",
	}
	for _, test := range UseProxyTests {
		if httpproxy.ExportUseProxy(cfg, test.host+":80") != test.match {
			t.Errorf("useProxy(%v) = %v, want %v", test.host, !test.match, test.match)
		}
	}
}

func TestInvalidNoProxy(t *testing.T) {
	cfg := &httpproxy.Config{
		NoProxy: ":1",
	}
	httpproxy.ExportUseProxy(cfg, "example.com:80") // should not panic
}
