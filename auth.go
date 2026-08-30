// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// ProxyAuthenticator authenticates the clients of an explicit forward proxy. It is consulted
// once per request addressed to the proxy, so the CONNECT that opens a tunnel authenticates
// everything carried on it. Implementations must be safe for concurrent use.
type ProxyAuthenticator interface {
	// Authenticate reports the client's identity. It must not read the body. An empty
	// identity is allowed, for an authenticator matching on the client address for example,
	// but it is indistinguishable from an unauthenticated request and no revocation can
	// sweep on it.
	Authenticate(r *http.Request) (identity string, ok bool)
	// Challenges returns the Proxy-Authenticate values a 407 carries, one per offered scheme.
	// Returning none answers 403 instead, which is the honest reply when nothing the client
	// could present would change the answer.
	Challenges(r *http.Request) []string
}

// BasicAuth returns a [ProxyAuthenticator] for the Basic scheme of RFC 7617, reporting the
// username as the identity. The proxy holds no credential of its own: verify looks them up
// wherever they live, so a password can stay hashed. A nil verify refuses every client.
//
// Basic sends the credentials on every request, encoded rather than encrypted, so reach the
// proxy with [Proxy.ListenAndServeTLS] or they cross the network in the clear.
func BasicAuth(realm string, verify func(username, password string) bool) ProxyAuthenticator {
	return basicAuth{
		// The realm is a quoted-string, so a quote or a backslash in it would end the header
		// value early and let the caller write a challenge the proxy never meant to offer.
		challenge: `Basic realm="` + quoteEscaper.Replace(realm) + `", charset="UTF-8"`,
		verify:    verify,
	}
}

var quoteEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

type basicAuth struct {
	verify    func(username, password string) bool
	challenge string
}

func (a basicAuth) Authenticate(r *http.Request) (string, bool) {
	if a.verify == nil {
		return "", false
	}
	username, password, ok := parseBasicCredentials(r.Header.Get(HeaderProxyAuthorization))
	if !ok || !a.verify(username, password) {
		return "", false
	}
	return username, true
}

func (a basicAuth) Challenges(*http.Request) []string { return []string{a.challenge} }

// parseBasicCredentials splits a Basic credential into its username and password. The split is
// on the first colon: a password may hold one, a username may not.
func parseBasicCredentials(header string) (username, password string, ok bool) {
	scheme, encoded, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimLeft(encoded, " "))
	if err != nil {
		return "", "", false
	}
	username, password, found = strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return username, password, true
}
