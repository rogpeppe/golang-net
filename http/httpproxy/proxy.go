package httpproxy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Config holds configuration for HTTP proxy settings. See
// FromEnvironment for details.
type Config struct {
	// HTTPProxy represents the value of the HTTP_PROXY or
	// http_proxy environment variable. It will be used as the proxy
	// URL for HTTP requests and HTTPS requests unless overridden by
	// HTTPSProxy or NoProxy.
	HTTPProxy string

	// HTTPSProxy represents the HTTPS_PROXY or https_proxy
	// environment variable. It will be used as the proxy URL for
	// HTTPS requests unless overridden by NoProxy.
	HTTPSProxy string

	// NoProxy represents the NO_PROXY or no_proxy environment
	// variable. It specifies URLs that should be excluded from
	// proxying as a comma-separated list of domain names or a
	// single asterisk (*) to indicate that no proxying should be
	// done. A domain name matches that name and all subdomains. A
	// domain name with a leading "." matches subdomains only. For
	// example "foo.com" matches "foo.com" and "bar.foo.com";
	// ".y.com" matches "x.y.com" but not "y.com".
	NoProxy string
}

// FromEnvironment returns a Config instance populated from the
// environment variables HTTP_PROXY, HTTPS_PROXY and NO_PROXY (or the
// lowercase versions thereof). HTTPS_PROXY takes precedence over
// HTTP_PROXY for https requests.
//
// The environment values may be either a complete URL or a
// "host[:port]", in which case the "http" scheme is assumed. An error
// is returned if the value is a different form.
//
// Note that this should be used with care in a situation where the
// program might be running in a CGI environment (see
// golang.org/s/cgihttpproxy for details). If it might be, then it's a
// good idea to avoid using a proxy when the REQUEST_METHOD environment
// variable is set.
func FromEnvironment() *Config {
	return &Config{
		HTTPProxy:  getEnvAny("HTTP_PROXY", "http_proxy"),
		HTTPSProxy: getEnvAny("HTTPS_PROXY", "https_proxy"),
		NoProxy:    getEnvAny("NO_PROXY", "no_proxy"),
	}
}

func getEnvAny(names ...string) string {
	for _, n := range names {
		if val := os.Getenv(n); val != "" {
			return val
		}
	}
	return ""
}

// ProxyForRequest determines the URL to use for the given request.
//
// A nil URL and nil error are returned if no proxy is defined in the
// environment, or a proxy should not be used for the given request, as
// defined by NO_PROXY.
//
// As a special case, if req.URL.Host is "localhost" (with or without a
// port number), then a nil URL and nil error will be returned.
func (cfg *Config) ProxyForURL(reqURL *url.URL) (*url.URL, error) {
	var proxy string
	if reqURL.Scheme == "https" {
		proxy = cfg.HTTPSProxy
	}
	if proxy == "" {
		proxy = cfg.HTTPProxy
	}
	if proxy == "" {
		return nil, nil
	}
	if !cfg.useProxy(canonicalAddr(reqURL)) {
		return nil, nil
	}
	proxyURL, err := url.Parse(proxy)
	if err != nil ||
		(proxyURL.Scheme != "http" &&
			proxyURL.Scheme != "https" &&
			proxyURL.Scheme != "socks5") {
		// proxy was bogus. Try prepending "http://" to it and
		// see if that parses correctly. If not, we fall
		// through and complain about the original one.
		if proxyURL, err := url.Parse("http://" + proxy); err == nil {
			return proxyURL, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address %q: %v", proxy, err)
	}
	return proxyURL, nil
}

// useProxy reports whether requests to addr should use a proxy,
// according to the NO_PROXY or no_proxy environment variable.
// addr is always a canonicalAddr with a host and port.
func (cfg *Config) useProxy(addr string) bool {
	if len(addr) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return false
		}
	}

	noProxy := cfg.NoProxy
	if noProxy == "*" {
		return false
	}

	addr = strings.ToLower(strings.TrimSpace(addr))
	if hasPort(addr) {
		addr = addr[:strings.LastIndex(addr, ":")]
	}

	for _, p := range strings.Split(noProxy, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if len(p) == 0 {
			continue
		}
		if hasPort(p) {
			p = p[:strings.LastIndex(p, ":")]
		}
		if addr == p {
			return false
		}
		if len(p) == 0 {
			// There is no host part, likely the entry is malformed; ignore.
			continue
		}
		if p[0] == '.' && (strings.HasSuffix(addr, p) || addr == p[1:]) {
			// no_proxy ".foo.com" matches "bar.foo.com" or "foo.com"
			return false
		}
		if p[0] != '.' && strings.HasSuffix(addr, p) && addr[len(addr)-len(p)-1] == '.' {
			// no_proxy "foo.com" matches "bar.foo.com"
			return false
		}
	}
	return true
}

var portMap = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

// canonicalAddr returns url.Host but always with a ":port" suffix
func canonicalAddr(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(addr, port)
}

// Given a string of the form "host", "host:port", or "[ipv6::address]:port",
// return true if the string includes a port.
func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

func idnaASCII(v string) (string, error) {
	// TODO: Consider removing this check after verifying performance is okay.
	// Right now punycode verification, length checks, context checks, and the
	// permissible character tests are all omitted. It also prevents the ToASCII
	// call from salvaging an invalid IDN, when possible. As a result it may be
	// possible to have two IDNs that appear identical to the user where the
	// ASCII-only version causes an error downstream whereas the non-ASCII
	// version does not.
	// Note that for correct ASCII IDNs ToASCII will only do considerably more
	// work, but it will not cause an allocation.
	if isASCII(v) {
		return v, nil
	}
	return idna.Lookup.ToASCII(v)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
