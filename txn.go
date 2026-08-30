package edge

import (
	"fmt"
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
// block, while write transactions are serialized by the proxy. A write Txn
// must be finalized with [Txn.Commit] or [Txn.Abort]. Routing requests never
// block, even while a write transaction is in progress.
type Txn struct {
	p       *Proxy
	rootTxn *tXn
	write   bool
}

// addImpliedAuthority registers the authority entry an interceptor implies, or bumps the
// reference count of the one already there.
func (txn *Txn) addImpliedAuthority(ic *Interceptor) error {
	authority, err := txn.p.impliedAuthorityFor(ic)
	if err != nil {
		return err
	}
	if txn.p.cfg.ca == nil {
		return fmt.Errorf("%w: interceptor %s needs to intercept %s",
			ErrNoCertificateAuthority, ic.pattern.str, authority.pattern.str)
	}

	t := txn.rootTxn
	existing := t.searchAuthority(authority)
	switch {
	case existing == nil:
		authority.refs = 1
		return t.insert(authority, modeInsert)
	case !existing.implicit && existing.action == Intercept:
		// The authority is already intercepted by a declaration the caller owns. The
		// interceptor rides on it and takes no reference on a decision it did not create.
		return nil
	case !existing.implicit:
		// The tunnel says do not look at this authority, the interceptor says handle its requests.
		// Nothing can honour both, and the interceptor is the one that would silently never run.
		return fmt.Errorf("%w: %s is %s, so interceptor %s would never run",
			ErrAuthorityConflict, existing.pattern.str, existing.action, ic.pattern.str)
	default:
		return replaceAuthorityRefs(t, existing, existing.refs+1)
	}
}

// dropImpliedAuthority releases one reference on the authority an interceptor implied,
// removing it once the last interceptor that needed it is gone.
func (txn *Txn) dropImpliedAuthority(ic *Interceptor) {
	authority, err := txn.p.impliedAuthorityFor(ic)
	if err != nil {
		return
	}

	t := txn.rootTxn
	existing := t.searchAuthority(authority)
	if existing == nil || !existing.implicit {
		return
	}
	if existing.refs > 1 {
		_ = replaceAuthorityRefs(t, existing, existing.refs-1)
		return
	}
	t.delete(existing)
}

// replaceAuthorityRefs swaps an entry for a copy holding a different reference count. Entries are
// immutable once published, so the count cannot be bumped in place.
func replaceAuthorityRefs(t *tXn, existing *Interceptor, refs uint32) error {
	next := *existing
	next.refs = refs
	if _, ok := t.delete(existing); !ok {
		return fmt.Errorf("internal error: authority %s vanished during refcount update", existing.pattern.str)
	}
	return t.insert(&next, modeInsert)
}

// AddInterceptor registers a new interceptor for the given methods, pattern and matchers. On success, it returns the newly registered [Interceptor].
// If an error occurs, it returns one of the following:
//   - [*PatternError]: If the pattern syntax is invalid.
//   - [*InterceptorConflictError]: If the interceptor conflict with others.
//   - [*InterceptorNameConflictError]: If the interceptor name is already registered.
//   - [ErrInvalidInterceptor]: If the method is invalid, the handler is nil or the pattern is empty.
//   - [ErrInvalidConfig]: If the provided option are invalid.
//   - [ErrInvalidMatcher]: If the provided matcher options are invalid.
//   - [ErrReadOnlyTxn]: On write in a read-only transaction.
//
// To override an existing handler, use [Txn.UpdateInterceptor].
func (txn *Txn) AddInterceptor(methods []string, pattern string, handler HandlerFunc, opts ...InterceptorOption) (*Interceptor, error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return nil, ErrReadOnlyTxn
	}

	ic, err := txn.p.newInterceptor(methods, pattern, handler, opts...)
	if err != nil {
		return nil, err
	}

	if err = txn.addImpliedAuthority(ic); err != nil {
		return nil, err
	}
	if err = txn.rootTxn.insert(ic, modeInsert); err != nil {
		return nil, err
	}
	return ic, nil
}

// UpdateInterceptor override an existing interceptor for the given methods, pattern and matchers. On success, it returns the newly registered [Interceptor].
// If an error occurs, it returns one of the following:
//   - [*PatternError]: If the pattern syntax is invalid.
//   - [ErrInterceptorNotFound]: If the interceptor does not exist.
//   - [*InterceptorNameConflictError]: If the interceptor name is already registered.
//   - [ErrInvalidInterceptor]: If the method is invalid, the handler is nil or the pattern is empty.
//   - [ErrInvalidConfig]: If the provided option are invalid.
//   - [ErrInvalidMatcher]: If the provided matcher options are invalid.
//   - [ErrReadOnlyTxn]: On write in a read-only transaction.
//
// Interceptor-specific options and middleware must be reapplied when updating one. If not, any middleware and option will
// be removed (or reset to their default value), and the interceptor will fall back to using global configuration (if any).
// To add a new handler, use [Txn.AddInterceptor].
func (txn *Txn) UpdateInterceptor(methods []string, pattern string, handler HandlerFunc, opts ...InterceptorOption) (*Interceptor, error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	if !txn.write {
		return nil, ErrReadOnlyTxn
	}

	ic, err := txn.p.newInterceptor(methods, pattern, handler, opts...)
	if err != nil {
		return nil, err
	}

	if err = txn.rootTxn.insert(ic, modeUpdate); err != nil {
		return nil, err
	}

	return ic, nil
}

// DeleteInterceptor deletes an existing interceptor for the given methods, pattern and matchers. On success, it returns the deleted [Interceptor].
// If an error occurs, it returns one of the following:
//   - [*PatternError]: If the pattern syntax is invalid.
//   - [ErrInterceptorNotFound]: If the interceptor does not exist.
//   - [ErrInvalidInterceptor]: If the method is invalid or the pattern is empty.
//   - [ErrInvalidConfig]: If the provided options are invalid.
//   - [ErrInvalidMatcher]: If the provided matcher options are invalid.
//   - [ErrReadOnlyTxn]: On write in a read-only transaction.
func (txn *Txn) DeleteInterceptor(methods []string, pattern string, opts ...MatcherOption) (*Interceptor, error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return nil, ErrReadOnlyTxn
	}

	for _, method := range methods {
		if !validMethod(method) {
			return nil, fmt.Errorf("%w: invalid method '%s'", ErrInvalidInterceptor, method)
		}
	}

	pat, _, err := txn.p.parsePattern(pattern)
	if err != nil {
		return nil, err
	}

	ic := &Interceptor{pattern: pat}

	for _, opt := range opts {
		if err = opt.applyMatcher(sealedOption{proxy: txn.p, interceptor: ic}); err != nil {
			return nil, err
		}
	}

	if len(ic.matchers) > txn.p.cfg.maxMatchers {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInterceptor, ErrTooManyMatchers)
	}

	// If this interceptor is registered with methods, push the internal matcher at first position.
	if len(methods) > 0 {
		// As a defensive mesure, keep our own copy of the provided slice.
		ic.methods = make([]string, len(methods))
		copy(ic.methods, methods)
		slices.Sort(ic.methods)
		ic.methods = slices.Compact(ic.methods)
	}

	ic, deleted := txn.rootTxn.delete(ic)
	if !deleted {
		return nil, newInterceptorNotFoundError(ic)
	}
	txn.dropImpliedAuthority(ic)

	return ic, nil
}

// removeInterceptor deletes an existing interceptor that match the provided [Interceptor] pattern and matchers. On success, it returns
// the deleted [Interceptor]. If an error occurs, it returns one of the following:
//   - [ErrInterceptorNotFound]: If the interceptor does not exist.
//   - [ErrInvalidInterceptor]: If the interceptor is missing.
//   - [ErrReadOnlyTxn]: On write in a read-only transaction.
func (txn *Txn) removeInterceptor(ic *Interceptor) (*Interceptor, error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return nil, ErrReadOnlyTxn
	}

	if ic == nil || ic.hbase == nil {
		return nil, ErrInvalidInterceptor
	}

	ic, deleted := txn.rootTxn.delete(ic)
	if !deleted {
		return nil, newInterceptorNotFoundError(ic)
	}
	txn.dropImpliedAuthority(ic)

	return ic, nil
}

// Truncate empties the tree, removing the interceptors and the authority entries together.
// Truncating on a read-only transaction returns ErrReadOnlyTxn.
func (txn *Txn) Truncate() error {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	if !txn.write {
		return ErrReadOnlyTxn
	}
	txn.rootTxn.truncate()
	return nil
}

// Has allows to check if the given methods, pattern and matchers exactly match a registered interceptor.
// See also [Txn.Interceptor] as an alternative.
func (txn *Txn) Has(methods []string, pattern string, matchers ...Matcher) bool {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	return txn.Interceptor(methods, pattern, matchers...) != nil
}

// Interceptor performs a lookup for a registered interceptor matching the given methods, pattern and matchers. It returns the [Interceptor] if a
// match is found or nil otherwise. See also [Txn.Has] or [Iter.Interceptors] as an alternative.
func (txn *Txn) Interceptor(methods []string, pattern string, matchers ...Matcher) *Interceptor {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	root := txn.rootTxn.patterns
	matched := root.searchPattern(patternKey(pattern))
	if matched == nil || !matched.isLeaf() {
		return nil
	}

	idx := slices.IndexFunc(matched.entries, func(r *Interceptor) bool {
		return r.pattern.path != "" && r.pattern.str == pattern &&
			slicesutil.EqualUnsorted(r.methods, methods) && r.matchersEqual(matchers)
	})
	if idx < 0 {
		return nil
	}
	return matched.entries[idx]
}

// ActionFor reports what the proxy would do with a connection to target, resolved on the tree
// this transaction sees rather than on the published one. A write transaction can therefore
// check the effect of a change before it commits. See [Proxy.ActionFor].
func (txn *Txn) ActionFor(target Target) Action {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	t := txn.rootTxn
	// The context comes from the pool of the tree the transaction forked from. Its
	// capacities are a sizing hint that the lookup grows when it has to, and nothing on the
	// authority path reads the tree the context was allocated for.
	pool := &t.tree.pool
	c := pool.Get().(*Context)
	defer pool.Put(c)

	return resolveAction(t.patterns, t.authorities, c, target)
}

// Name performs a lookup for a registered interceptor matching the given name. It returns
// the [Interceptor] if a match is found or nil otherwise. See also [Txn.Interceptor] as an alternative.
func (txn *Txn) Name(name string) *Interceptor {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	root := txn.rootTxn.names
	matched := root.searchName(name)
	if matched == nil || !matched.isLeaf() || matched.entries[0].name != name {
		return nil
	}

	return matched.entries[0]
}

// InterceptorsLen returns the number of registered interceptors.
func (txn *Txn) InterceptorsLen() int {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	return txn.rootTxn.interceptors
}

// AuthoritiesLen returns the number of registered authority entries. See
// [Proxy.AuthoritiesLen].
func (txn *Txn) AuthoritiesLen() int {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	return txn.rootTxn.authorities
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
	// Authorities are published first. An interceptor visible before the authority entry that intercepts its
	// authority would never fire; an authority entry visible before its interceptor only means the authority
	// is intercepted and forwarded unchanged for an instant.
	txn.p.tree.Store(newRoot)

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
