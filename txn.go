package edge

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/fox-toolkit/edge/internal/slicesutil"
	"golang.org/x/net/http/httpguts"
)

// Txn is a read or write transaction on the routing tree.
//
// A Txn must not be used concurrently by multiple goroutines. It is however
// safe to run multiple transactions from different goroutines, each on its
// own Txn. Read transactions operate on a point-in-time snapshot and never
// block, while write transactions are serialized by the router. A write Txn
// must be finalized with [Txn.Commit] or [Txn.Abort]. Routing requests never
// block, even while a write transaction is in progress.
type Txn struct {
	p       *Proxy
	rootTxn *tXn
	// ruleTxn is created on the first route registration that implies an interception
	// rule, and committed with the routing tree so the two never disagree.
	ruleTxn *tXn
	write   bool
}

// rules returns the rule transaction, starting it on first use.
func (txn *Txn) rules() *tXn {
	if txn.ruleTxn == nil {
		txn.ruleTxn = txn.p.getRules().txn()
	}
	return txn.ruleTxn
}

// addImplicitRule registers the interception rule a route implies, or bumps the reference
// count of the one already there. A route that names no authority implies nothing.
func (txn *Txn) addImplicitRule(route *Route) error {
	rule, err := txn.p.implicitRuleFor(route)
	if err != nil || rule == nil {
		return err
	}
	if txn.p.cfg.ca == nil {
		return fmt.Errorf("%w: route %s needs to intercept %s, configure one with WithCA",
			ErrNoCertificateAuthority, route.pattern.str, rule.pattern.str)
	}

	t := txn.rules()
	existing := t.findRule(rule)
	switch {
	case existing == nil:
		rule.refs = 1
		return t.insert(rule, modeInsert)
	case !existing.implicit:
		// An explicit rule already decides this authority, whatever it decides.
		return nil
	default:
		return replaceRuleRefs(t, existing, existing.refs+1)
	}
}

// dropImplicitRule releases one reference on the rule a route implied, removing it once the
// last route that needed it is gone.
func (txn *Txn) dropImplicitRule(route *Route) {
	rule, err := txn.p.implicitRuleFor(route)
	if err != nil || rule == nil {
		return
	}

	t := txn.rules()
	existing := t.findRule(rule)
	if existing == nil || !existing.implicit {
		return
	}
	if existing.refs > 1 {
		_ = replaceRuleRefs(t, existing, existing.refs-1)
		return
	}
	t.delete(existing)
}

// replaceRuleRefs swaps a rule for a copy holding a different reference count. Routes are
// immutable once published, so the count cannot be bumped in place.
func replaceRuleRefs(t *tXn, existing *Route, refs uint32) error {
	next := *existing
	next.refs = refs
	if _, ok := t.delete(existing); !ok {
		return fmt.Errorf("internal error: rule %s vanished during refcount update", existing.pattern.str)
	}
	return t.insert(&next, modeInsert)
}

// Add registers a new route for the given methods, pattern and matchers. On success, it returns the newly registered [Route].
// If an error occurs, it returns one of the following:
//   - [*PatternError]: If the pattern syntax is invalid.
//   - [*RouteConflictError]: If the route conflict with others.
//   - [*RouteNameConflictError]: If the route name is already registered.
//   - [ErrInvalidRoute]: If the method is invalid, the handler is nil or the pattern is empty.
//   - [ErrInvalidConfig]: If the provided route options are invalid.
//   - [ErrInvalidMatcher]: If the provided matcher options are invalid.
//   - [ErrReadOnlyTxn]: On write in a read-only transaction.
//
// To override an existing handler, use [Txn.Update].
func (txn *Txn) Add(methods []string, pattern string, handler HandlerFunc, opts ...RouteOption) (*Route, error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return nil, ErrReadOnlyTxn
	}

	rte, err := txn.p.NewRoute(methods, pattern, handler, opts...)
	if err != nil {
		return nil, err
	}

	if err = txn.addImplicitRule(rte); err != nil {
		return nil, err
	}
	if err = txn.rootTxn.insert(rte, modeInsert); err != nil {
		return nil, err
	}
	return rte, nil
}

// AddRoute registers a new [Route]. If an error occurs, it returns one of the following:
//   - [*RouteConflictError]: If the route conflict with others.
//   - [*RouteNameConflictError]: If the route name is already registered.
//   - [ErrInvalidRoute]: If the route is missing.
//   - [ErrReadOnlyTxn]: On write in a read-only transaction.
//
// To override an existing route, use [Txn.UpdateRoute].
func (txn *Txn) AddRoute(route *Route) error {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return ErrReadOnlyTxn
	}
	if route == nil || route.hbase == nil {
		return ErrInvalidRoute
	}

	if err := txn.addImplicitRule(route); err != nil {
		return err
	}
	return txn.rootTxn.insert(route, modeInsert)
}

// Update override an existing route for the given methods, pattern and matchers. On success, it returns the newly registered [Route].
// If an error occurs, it returns one of the following:
//   - [*PatternError]: If the pattern syntax is invalid.
//   - [ErrRouteNotFound]: If the route does not exist.
//   - [*RouteNameConflictError]: If the route name is already registered.
//   - [ErrInvalidRoute]: If the method is invalid, the handler is nil or the pattern is empty.
//   - [ErrInvalidConfig]: If the provided route options are invalid.
//   - [ErrInvalidMatcher]: If the provided matcher options are invalid.
//   - [ErrReadOnlyTxn]: On write in a read-only transaction.
//
// Route-specific option and middleware must be reapplied when updating a route. if not, any middleware and option will
// be removed (or reset to their default value), and the route will fall back to using global configuration (if any).
// To add a new handler, use [Txn.Add].
func (txn *Txn) Update(methods []string, pattern string, handler HandlerFunc, opts ...RouteOption) (*Route, error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	if !txn.write {
		return nil, ErrReadOnlyTxn
	}

	rte, err := txn.p.NewRoute(methods, pattern, handler, opts...)
	if err != nil {
		return nil, err
	}

	if err = txn.rootTxn.insert(rte, modeUpdate); err != nil {
		return nil, err
	}

	return rte, nil
}

// UpdateRoute override an existing [Route] for the given new [Route].
// If an error occurs, it returns one of the following:
//   - [ErrRouteNotFound]: If the route does not exist.
//   - [*RouteNameConflictError]: If the route name is already registered.
//   - [ErrInvalidRoute]: If the route is missing.
//   - [ErrReadOnlyTxn]: On write in a read-only transaction.
//
// To add a new route, use [Txn.AddRoute].
func (txn *Txn) UpdateRoute(route *Route) error {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return ErrReadOnlyTxn
	}
	if route == nil || route.hbase == nil {
		return ErrInvalidRoute
	}

	return txn.rootTxn.insert(route, modeUpdate)
}

// Delete deletes an existing route for the given methods, pattern and matchers. On success, it returns the deleted [Route].
// If an error occurs, it returns one of the following:
//   - [*PatternError]: If the pattern syntax is invalid.
//   - [ErrRouteNotFound]: If the route does not exist.
//   - [ErrInvalidRoute]: If the method is invalid or the pattern is empty.
//   - [ErrInvalidConfig]: If the provided options are invalid.
//   - [ErrInvalidMatcher]: If the provided matcher options are invalid.
//   - [ErrReadOnlyTxn]: On write in a read-only transaction.
func (txn *Txn) Delete(methods []string, pattern string, opts ...MatcherOption) (*Route, error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return nil, ErrReadOnlyTxn
	}

	for _, method := range methods {
		if !validMethod(method) {
			return nil, fmt.Errorf("%w: invalid method '%s'", ErrInvalidRoute, method)
		}
	}

	pat, _, err := txn.p.parsePattern(pattern)
	if err != nil {
		return nil, err
	}

	rte := &Route{pattern: pat}

	for _, opt := range opts {
		if err = opt.applyMatcher(sealedOption{route: rte, cfg: txn.p.cfg}); err != nil {
			return nil, err
		}
	}

	if len(rte.matchers) > txn.p.cfg.maxMatchers {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRoute, ErrTooManyMatchers)
	}

	// If this route is registered with methods, push the internal matcher at first position.
	if len(methods) > 0 {
		// As a defensive mesure, keep our own copy of the provided slice.
		rte.methods = make([]string, len(methods))
		copy(rte.methods, methods)
		slices.Sort(rte.methods)
		rte.methods = slices.Compact(rte.methods)
	}

	route, deleted := txn.rootTxn.delete(rte)
	if !deleted {
		return nil, newRouteNotFoundError(rte)
	}
	txn.dropImplicitRule(route)

	return route, nil
}

// DeleteRoute deletes an existing route that match the provided [Route] pattern and matchers. On success, it returns
// the deleted [Route]. If an error occurs, it returns one of the following:
//   - [ErrRouteNotFound]: If the route does not exist.
//   - [ErrInvalidRoute]: If the route is missing.
//   - [ErrReadOnlyTxn]: On write in a read-only transaction.
func (txn *Txn) DeleteRoute(route *Route) (*Route, error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return nil, ErrReadOnlyTxn
	}

	if route == nil || route.hbase == nil {
		return nil, ErrInvalidRoute
	}

	rte, deleted := txn.rootTxn.delete(route)
	if !deleted {
		return nil, newRouteNotFoundError(route)
	}
	txn.dropImplicitRule(rte)

	return rte, nil
}

// Truncate remove all routes registered in the router. Truncating on a read-only transaction returns ErrReadOnlyTxn.
func (txn *Txn) Truncate() error {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	if !txn.write {
		return ErrReadOnlyTxn
	}
	txn.rootTxn.truncate()
	txn.dropAllImplicitRules()
	return nil
}

// dropAllImplicitRules removes every rule derived from a route, leaving the explicit ones.
func (txn *Txn) dropAllImplicitRules() {
	t := txn.rules()
	var implicit []*Route
	it := Iter{patterns: t.patterns, names: t.names, methods: t.methods, maxDepth: t.maxDepth}
	for rule := range it.All() {
		if rule.implicit {
			implicit = append(implicit, rule)
		}
	}
	for _, rule := range implicit {
		t.delete(rule)
	}
}

// Has allows to check if the given methods, pattern and matchers exactly match a registered route.
// See also [Txn.Route] as an alternative.
func (txn *Txn) Has(methods []string, pattern string, matchers ...Matcher) bool {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	return txn.Route(methods, pattern, matchers...) != nil
}

// Route performs a lookup for a registered route matching the given methods, pattern and matchers. It returns the [Route] if a
// match is found or nil otherwise. See also [Txn.Has] or [Iter.Routes] as an alternative.
func (txn *Txn) Route(methods []string, pattern string, matchers ...Matcher) *Route {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	root := txn.rootTxn.patterns
	matched := root.searchPattern(pattern)
	if matched == nil || !matched.isLeaf() {
		return nil
	}

	idx := slices.IndexFunc(matched.routes, func(r *Route) bool {
		return r.pattern.str == pattern && slicesutil.EqualUnsorted(r.methods, methods) && r.matchersEqual(matchers)
	})
	if idx < 0 {
		return nil
	}
	return matched.routes[idx]
}

// Name performs a lookup for a registered route matching the given route name. It returns
// the [Route] if a match is found or nil otherwise. See also [Txn.Route] as an alternative.
func (txn *Txn) Name(name string) *Route {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	root := txn.rootTxn.names
	matched := root.searchName(name)
	if matched == nil || !matched.isLeaf() || matched.routes[0].name != name {
		return nil
	}

	return matched.routes[0]
}

// Match performs a route lookup for the given target and request, returning the matching
// [Route] if there is one. No handler runs and no parameter is captured; use [Txn.Lookup]
// when the captures are needed.
func (txn *Txn) Match(target Target, r *http.Request) (route *Route, tsr bool) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if r == nil || r.Method == "" {
		return nil, false
	}

	tree := txn.rootTxn.tree
	c := tree.pool.Get().(*Context)
	defer tree.pool.Put(c)

	target = target.normalized()
	c.reset(nil, r, target.Scheme, target.Host, target.Port)

	path, ok := txn.p.normalizeForMatch(routingPath(r))
	if !ok {
		return nil, false
	}

	idx, n, tsr := txn.rootTxn.patterns.lookup(r.Method, target.Host, path, c, true)
	if n != nil {
		return n.routes[idx], tsr
	}
	return nil, false
}

// Lookup performs a route lookup for the given target and request, returning the matched
// [Route] along with a [Context] holding the captured parameters. The returned [Context]
// must be released with [Context.Close] once it is no longer used.
func (txn *Txn) Lookup(target Target, r *http.Request) (route *Route, cc *Context, tsr bool) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if r == nil || r.Method == "" {
		return nil, nil, false
	}

	tree := txn.rootTxn.tree
	c := tree.pool.Get().(*Context)

	target = target.normalized()
	c.reset(nil, r, target.Scheme, target.Host, target.Port)

	path, ok := txn.p.normalizeForMatch(routingPath(r))
	if !ok {
		tree.pool.Put(c)
		return nil, nil, false
	}

	idx, n, tsr := txn.rootTxn.patterns.lookup(r.Method, target.Host, path, c, false)
	if n != nil {
		c.route = n.routes[idx]
		return c.route, c, tsr
	}

	tree.pool.Put(c)
	return nil, nil, false
}

// Len returns the number of registered route.
func (txn *Txn) Len() int {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	return txn.rootTxn.size
}

// Commit finalize the transaction. This is a noop for read transactions, already aborted or
// committed transactions.
func (txn *Txn) Commit() {
	// Noop for a read transaction
	if !txn.write {
		return
	}

	// Check if already aborted or committed
	if txn.rootTxn == nil {
		return
	}

	newRoot := txn.rootTxn.commit()
	// Rules are published first. A route visible before the rule that intercepts its
	// authority would never fire; a rule visible before its route only means the authority
	// is intercepted and forwarded unchanged for an instant.
	if txn.ruleTxn != nil {
		txn.p.rules.Store(txn.ruleTxn.commit())
		txn.ruleTxn = nil
	}
	txn.p.routes.Store(newRoot)

	// Clear the txn
	txn.rootTxn = nil
	txn.p.mu.Unlock()
}

// Abort cancel the transaction. This is a noop for read transactions, already aborted or
// committed transactions.
func (txn *Txn) Abort() {
	// Noop for a read transaction
	if !txn.write {
		return
	}

	// Check if already aborted or committed
	if txn.rootTxn == nil {
		return
	}

	// Clear the txn
	txn.rootTxn = nil
	txn.ruleTxn = nil
	txn.p.mu.Unlock()
}

// Snapshot returns a point in time snapshot of the current state of the transaction.
// Returns a new read-only transaction or nil if the transaction is already aborted
// or committed.
func (txn *Txn) Snapshot() *Txn {
	if txn.rootTxn == nil {
		return nil
	}

	return &Txn{
		p:       txn.p,
		rootTxn: txn.rootTxn.clone(),
	}
}

func validMethod(method string) bool {
	/*
	     Method         = "OPTIONS"                ; Section 9.2
	                    | "GET"                    ; Section 9.3
	                    | "HEAD"                   ; Section 9.4
	                    | "POST"                   ; Section 9.5
	                    | "PUT"                    ; Section 9.6
	                    | "DELETE"                 ; Section 9.7
	                    | "TRACE"                  ; Section 9.8
	                    | "CONNECT"                ; Section 9.9
	                    | extension-method
	   extension-method = token
	     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}
