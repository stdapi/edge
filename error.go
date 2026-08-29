// Copyright 2022 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	// ErrInterceptorNotFound is returned when no interceptor matches the lookup.
	ErrInterceptorNotFound = errors.New("interceptor not found")
	// ErrInvalidInterceptor is returned when an interceptor cannot be built from the given arguments.
	ErrInvalidInterceptor = errors.New("invalid interceptor")
	// ErrTunnelNotFound is returned when no tunnel is registered for an authority.
	ErrTunnelNotFound = errors.New("tunnel not found")
	// ErrInvalidAuthority is returned when an authority pattern cannot be parsed.
	ErrInvalidAuthority = errors.New("invalid authority")
	// ErrReadOnlyTxn is returned on a write in a read-only transaction.
	ErrReadOnlyTxn = errors.New("write on read-only transaction")
	// ErrSettledTxn is the panic value of an operation on a committed or aborted transaction.
	ErrSettledTxn = errors.New("transaction settled")
	// ErrTooManyMatchers is returned when an interceptor carries more matchers than configured.
	ErrTooManyMatchers = errors.New("too many matchers")
	// ErrInvalidConfig is returned when a proxy or option is invalid.
	ErrInvalidConfig = errors.New("invalid config")
	// ErrInvalidMatcher is returned when a matcher cannot be built.
	ErrInvalidMatcher = errors.New("invalid matcher")
	// ErrNoCertificateAuthority is returned when interception is configured without a CA.
	ErrNoCertificateAuthority = errors.New("no certificate authority")
	// ErrProxyClosed is returned by the serving methods after Shutdown or Close.
	ErrProxyClosed = errors.New("proxy closed")
	// ErrConnectionRejected is returned when the proxy refuses a connection.
	ErrConnectionRejected = errors.New("connection rejected")
	// ErrAuthorityConflict is returned when a tunnel and the interceptors registered under
	// the same authority disagree on what should happen to its connections.
	ErrAuthorityConflict = errors.New("authority conflict")
)

// InterceptorConflictError represents a conflict that occurred during route registration.
// It contains the interceptor being registered, and the existing interceptors that caused the conflict.
type InterceptorConflictError struct {
	// New is the interceptor that was being registered when the conflict was detected.
	New *Interceptor
	// Conflicts contains the previously registered interceptors that conflict with New.
	Conflicts []*Interceptor
	// isShadowed indicate that the New route shadow other interceptors.
	isShadowed bool
}

func (e *InterceptorConflictError) Error() string {
	sb := new(strings.Builder)
	sb.WriteString("interceptor conflict: new interceptor\n")
	entryf(sb, e.New, 4, true)

	if e.isShadowed {
		if e.New.pattern.optionalCatchAll {
			sb.WriteString("\nis shadowed by")
		} else {
			sb.WriteString("\nwould shadow")
		}
	} else {
		sb.WriteString("\nconflicts with")
	}

	for _, conflict := range e.Conflicts {
		sb.WriteByte('\n')
		entryf(sb, conflict, 4, true)
	}

	return sb.String()
}

// InterceptorNameConflictError represents a conflict that occurred during interceptor name registration.
// It contains the interceptor being registered, and the existing route that caused the conflict.
type InterceptorNameConflictError struct {
	// New is the interceptor that was being registered when the conflict was detected.
	New *Interceptor
	// Conflict is the previously registered interceptor that conflicts with New.
	Conflict *Interceptor
}

func (e *InterceptorNameConflictError) Error() string {
	sb := new(strings.Builder)
	sb.WriteString("interceptor name already registered: new interceptor\n")
	entryf(sb, e.New, 4, true)
	sb.WriteString("\nconflicts with\n")
	entryf(sb, e.Conflict, 4, true)
	return sb.String()
}

func newInterceptorNotFoundError(route *Interceptor) error {
	sb := new(strings.Builder)
	sb.WriteString("interceptor\n")
	entryf(sb, route, 4, false)
	sb.WriteString("\nis not registered")
	return fmt.Errorf("%w: %s", ErrInterceptorNotFound, sb.String())
}

type PatternError struct {
	err     error  // wrapped error
	Pattern string // provided pattern
	Type    string // hostname | path
	Reason  string // syntax | parameter | regexp | constraint
	Hint    string // hint
	Start   int    // start offset of the offending segment
	End     int    // end offset of the offending segment
}

// Unwrap returns the underlying error, if any.
func (e *PatternError) Unwrap() error {
	return e.err
}

// Error returns a human-readable error message with a visual pointer to the offending segment.
func (e *PatternError) Error() string {
	var sb strings.Builder
	sb.WriteString("pattern: ")
	if e.Type != "" {
		sb.WriteString(e.Type)
		sb.WriteString(": ")
	}
	sb.WriteString(e.Reason)
	sb.WriteString(": ")
	sb.WriteString(e.Hint)
	if e.Pattern != "" {
		sb.WriteByte('\n')
		sb.WriteString("      ")
		sb.WriteString(e.Pattern)
		sb.WriteByte('\n')
		sb.WriteString("      ")

		start := min(max(e.Start, 0), len(e.Pattern))
		end := min(max(e.End, start), len(e.Pattern))
		sb.WriteString(strings.Repeat(" ", utf8.RuneCountInString(e.Pattern[:start])))
		sb.WriteString(strings.Repeat("^", max(utf8.RuneCountInString(e.Pattern[start:end]), 1)))
	}
	return sb.String()
}

func newPatternError(reason string, start, end int, msg string) *PatternError {
	return &PatternError{
		Reason: reason,
		Start:  start,
		End:    end,
		Hint:   msg,
	}
}
