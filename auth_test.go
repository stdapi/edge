// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// testUsers is the credential store the authenticator under test reads.
var testUsers = map[string]string{"alice": "secret", "bob": "hunter2"}

func testBasic() ProxyAuthenticator {
	return BasicAuth("edge", func(user, pass string) bool {
		want, ok := testUsers[user]
		return ok && want == pass
	})
}

// authProxyClient returns a client reaching origins through addr, authenticating as user.
func authProxyClient(addr, user, pass string, trust *x509.CertPool) *http.Client {
	c := proxyClient(addr, trust)
	c.Transport.(*http.Transport).Proxy = http.ProxyURL(&url.URL{
		Scheme: "http",
		Host:   addr,
		User:   url.UserPassword(user, pass),
	})
	return c
}

// rawConnect sends a CONNECT by hand so the proxy's own answer can be read. A Go client
// reports a refused CONNECT as an error and hides the response that carried the reason.
func rawConnect(t *testing.T, addr, authority, credentials string) *http.Response {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	req := "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n"
	if credentials != "" {
		req += HeaderProxyAuthorization + ": " + credentials + "\r\n"
	}
	_, err = io.WriteString(conn, req+"\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestProxyAuth_ChallengesAnUnauthenticatedConnect(t *testing.T) {
	p := Must(WithProxyAuth(testBasic()))
	require.NoError(t, p.AddTunnel("example.com"))
	addr := startProxy(t, p)

	resp := rawConnect(t, addr, "example.com:443", "")

	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	assert.Equal(t, `Basic realm="edge", charset="UTF-8"`, resp.Header.Get(HeaderProxyAuthenticate))
}

func TestProxyAuth_RefusesWrongCredentials(t *testing.T) {
	p := Must(WithProxyAuth(testBasic()))
	require.NoError(t, p.AddTunnel("example.com"))
	addr := startProxy(t, p)

	resp := rawConnect(t, addr, "example.com:443", "Basic YWxpY2U6d3Jvbmc=") // alice:wrong

	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
}

func TestProxyAuth_RunsBeforeTheAuthorityDecision(t *testing.T) {
	// Nothing admits this authority, so it would be refused with 403 once authenticated. An
	// unauthenticated client must not be able to tell the two apart.
	p := Must(WithProxyAuth(testBasic()))
	addr := startProxy(t, p)

	unauthenticated := rawConnect(t, addr, "unregistered.test:443", "")
	assert.Equal(t, http.StatusProxyAuthRequired, unauthenticated.StatusCode)

	authenticated := rawConnect(t, addr, "unregistered.test:443", "Basic YWxpY2U6c2VjcmV0") // alice:secret
	assert.Equal(t, http.StatusForbidden, authenticated.StatusCode)
}

// noChallengeAuth refuses everyone and offers nothing to present, the shape an allow list of
// client addresses has.
type noChallengeAuth struct{}

func (noChallengeAuth) Authenticate(*http.Request) (string, bool) { return "", false }
func (noChallengeAuth) Challenges(*http.Request) []string         { return nil }

func TestProxyAuth_NoChallengeAnswers403(t *testing.T) {
	p := Must(WithProxyAuth(noChallengeAuth{}))
	require.NoError(t, p.AddTunnel("example.com"))
	addr := startProxy(t, p)

	resp := rawConnect(t, addr, "example.com:443", "")

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get(HeaderProxyAuthenticate))
}

func TestProxyAuth_IdentityReachesTheHandler(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)

	p := Must(WithCA(ca), WithProxyAuth(testBasic()))
	p.MustAddInterceptor(nil, originHost(originURL)+"/*{any}", func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, c.Identity()), nil
	})
	addr := startProxy(t, p)

	resp, err := authProxyClient(addr, "alice", "secret", nil).Get(origin.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "alice", string(body))
}

// Every request on the plain path authenticates itself, so the identity a handler reads is
// the one its own request carried and never the one before it.
func TestProxyAuth_IdentityIsPerRequest(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)

	p := Must(WithCA(ca), WithProxyAuth(testBasic()))
	p.MustAddInterceptor(nil, originHost(originURL)+"/*{any}", func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, c.Identity()), nil
	})
	addr := startProxy(t, p)

	for _, want := range []struct{ user, pass string }{
		{"alice", "secret"},
		{"bob", "hunter2"},
		{"alice", "secret"},
	} {
		resp, gerr := authProxyClient(addr, want.user, want.pass, nil).Get(origin.URL)
		require.NoError(t, gerr)
		body, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, rerr)
		assert.Equal(t, want.user, string(body))
	}
}

func TestProxyAuth_SessionCarriesTheIdentityOfItsConnect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p := Must(WithCA(ca), WithTransport(tr), WithProxyAuth(testBasic()))
	p.MustAddInterceptor(nil, originHost(originURL)+"/*{any}", func(c *Context) (*http.Response, error) {
		// Nothing on an intercepted connection is challenged, so both must report the
		// identity the CONNECT that opened it carried.
		return Text(http.StatusOK, c.Session().Identity()+"/"+c.Identity()), nil
	})
	addr := startProxy(t, p)

	resp, err := authProxyClient(addr, "bob", "hunter2", ca.CertPool()).Get(origin.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "bob/bob", string(body))
}

func TestProxyAuth_NoAuthenticatorLeavesEveryoneIn(t *testing.T) {
	p := Must()
	require.NoError(t, p.AddTunnel("example.com"))
	addr := startProxy(t, p)

	// No authenticator, so the authority decision is what answers, and it admits this one.
	resp := rawConnect(t, addr, "unregistered.test:443", "")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get(HeaderProxyAuthenticate))
}

func TestWithProxyAuth_RejectsNil(t *testing.T) {
	_, err := New(WithProxyAuth(nil))
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestBasicAuth_NilVerifyRefusesEveryone(t *testing.T) {
	a := BasicAuth("edge", nil)
	r := httptest.NewRequest(http.MethodConnect, "https://example.com", nil)
	r.Header.Set(HeaderProxyAuthorization, "Basic YWxpY2U6c2VjcmV0")

	_, ok := a.Authenticate(r)
	assert.False(t, ok)
}

func TestBasicAuth_EscapesTheRealm(t *testing.T) {
	a := BasicAuth(`ed"ge\x`, func(string, string) bool { return true })
	assert.Equal(t, `Basic realm="ed\"ge\\x", charset="UTF-8"`, a.Challenges(nil)[0])
}

func TestParseBasicCredentials(t *testing.T) {
	cases := []struct {
		name, header, user, pass string
		ok                       bool
	}{
		{name: "valid", header: "Basic YWxpY2U6c2VjcmV0", user: "alice", pass: "secret", ok: true},
		{name: "scheme is case insensitive", header: "basic YWxpY2U6c2VjcmV0", user: "alice", pass: "secret", ok: true},
		{name: "extra space before the credentials", header: "Basic  YWxpY2U6c2VjcmV0", user: "alice", pass: "secret", ok: true},
		// A colon may appear in a password and never in a username, so the split is on the first.
		{name: "colon in the password", header: "Basic YTpiOmM=", user: "a", pass: "b:c", ok: true},
		{name: "utf8 credentials", header: "Basic w6lsw6huZTpzw6ljcmV0", user: "élène", pass: "sécret", ok: true},
		{name: "empty password", header: "Basic YWxpY2U6", user: "alice", pass: "", ok: true},
		{name: "empty header", header: ""},
		{name: "other scheme", header: "Bearer YWxpY2U6c2VjcmV0"},
		{name: "no scheme", header: "YWxpY2U6c2VjcmV0"},
		{name: "malformed base64", header: "Basic not-base64!"},
		{name: "no colon once decoded", header: "Basic YWxpY2U="},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, pass, ok := parseBasicCredentials(tc.header)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.user, user)
			assert.Equal(t, tc.pass, pass)
		})
	}
}

// Proxy-Authorization is hop-by-hop and holds a credential, so it must never reach an origin.
// The client sends it on every request of the plain path, and both the routed and the relayed
// path build the outbound request.
func TestProxyAuth_CredentialsNeverReachTheOrigin(t *testing.T) {
	seen := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(HeaderProxyAuthorization)
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	cases := []struct {
		name  string
		setup func(p *Proxy)
	}{
		{"intercepted", func(p *Proxy) {
			p.MustAddInterceptor(nil, originHost(originURL)+"/*{any}", func(c *Context) (*http.Response, error) {
				return c.Forward()
			})
		}},
		{"tunneled", func(p *Proxy) {
			require.NoError(t, p.AddTunnel(originHost(originURL)))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, cerr := GenerateCA()
			require.NoError(t, cerr)
			p := Must(WithCA(ca), WithProxyAuth(testBasic()))
			tc.setup(p)
			addr := startProxy(t, p)

			resp, gerr := authProxyClient(addr, "alice", "secret", nil).Get(origin.URL)
			require.NoError(t, gerr)
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			assert.Empty(t, <-seen, "the origin was handed the client's proxy credentials")
		})
	}
}

// The revocation sweep the identity exists for: a credential is withdrawn, and the
// connections already open are found through Sessions and closed.
func TestProxyAuth_SessionsReportTheIdentity(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)

	p := Must(WithCA(ca), WithProxyAuth(testBasic()))
	// The session is registered by the time a handler runs on it, so reading the sweep from
	// inside one needs no synchronisation with the connection being established.
	p.MustAddInterceptor(nil, originHost(originURL)+"/*{any}", func(c *Context) (*http.Response, error) {
		var found []string
		for s := range c.Proxy().Sessions() {
			if id := s.Identity(); id != "" {
				found = append(found, id)
			}
		}
		return Text(http.StatusOK, strings.Join(found, ",")), nil
	})
	addr := startProxy(t, p)

	resp, err := authProxyClient(addr, "alice", "secret", ca.CertPool()).Get(origin.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "alice", string(body))
}

// A CONNECT carried on an HTTP/2 stream reaches its session through connectStream rather
// than through the hijack, and the identity has to reach both. The tunnel branch registers
// the session before it answers, so the sweep below cannot race the connection.
func TestProxyAuth_IdentityOnAnHTTP2Connect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	p := Must(WithProxyAuth(testBasic()))
	require.NoError(t, p.AddTunnel(originHost(originURL)))
	addr := startProxy(t, p)

	// h2c to the proxy, opened by hand since http2.Transport has no proxy support.
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	req, err := http.NewRequest(http.MethodConnect, "https://"+originURL.Host, pr)
	require.NoError(t, err)
	req.Header.Set(HeaderProxyAuthorization, "Basic Ym9iOmh1bnRlcjI=") // bob:hunter2

	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var found []string
	for s := range p.Sessions() {
		found = append(found, s.Identity())
	}
	assert.Equal(t, []string{"bob"}, found)
}

func TestProxyAuth_RefusedHTTP2Connect(t *testing.T) {
	p := Must(WithProxyAuth(testBasic()))
	require.NoError(t, p.AddTunnel("example.com"))
	addr := startProxy(t, p)

	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	req, err := http.NewRequest(http.MethodConnect, "https://example.com:443", pr)
	require.NoError(t, err)

	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	assert.Equal(t, `Basic realm="edge", charset="UTF-8"`, resp.Header.Get(HeaderProxyAuthenticate))
}
