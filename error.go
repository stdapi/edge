// Copyright 2022 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	// ErrEntryNotFound is returned when no entry matches the lookup.
	ErrEntryNotFound = errors.New("entry not found")
	// ErrInvalidEntry is returned when an entry cannot be built from the given arguments.
	ErrInvalidEntry = errors.New("invalid entry")
	// ErrInvalidAuthority is returned when an authority pattern cannot be parsed.
	ErrInvalidAuthority = errors.New("invalid authority")
	// ErrReadOnlyTxn is returned on a write in a read-only transaction.
	ErrReadOnlyTxn = errors.New("write on read-only transaction")
	// ErrSettledTxn is the panic value of an operation on a committed or aborted transaction.
	ErrSettledTxn = errors.New("transaction settled")
	// ErrTooManyMatchers is returned when an entry carries more matchers than configured.
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
	// ErrTooManyOrigins is returned by [DatagramCtx.SendTo] when the flow has reached its
	// limit of origins.
	ErrTooManyOrigins = errors.New("too many origins for one datagram flow")
)

// EntryConflictError represents a conflict that occurred during entry registration.
// It contains the entry being registered, and the existing entries that caused the conflict.
type EntryConflictError struct {
	// New is the entry that was being registered when the conflict was detected.
	New *entry
	// Conflicts contains the previously registered entries that conflict with New.
	Conflicts []*entry
	// isShadowed indicate that the New entry shadow other entries.
	isShadowed bool
}

func (e *EntryConflictError) Error() string {
	sb := new(strings.Builder)
	sb.WriteString("entry conflict: new entry\n")
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

// EntryNameConflictError represents a conflict that occurred during entry name registration.
// It contains the entry being registered, and the existing entry that caused the conflict.
type EntryNameConflictError struct {
	// New is the entry that was being registered when the conflict was detected.
	New *entry
	// Conflict is the previously registered entry that conflicts with New.
	Conflict *entry
}

func (e *EntryNameConflictError) Error() string {
	sb := new(strings.Builder)
	sb.WriteString("entry name already registered: new entry\n")
	entryf(sb, e.New, 4, true)
	sb.WriteString("\nconflicts with\n")
	entryf(sb, e.Conflict, 4, true)
	return sb.String()
}

func newEntryNotFoundError(ic *entry) error {
	sb := new(strings.Builder)
	sb.WriteString("entry\n")
	entryf(sb, ic, 4, false)
	sb.WriteString("\nis not registered")
	return fmt.Errorf("%w: %s", ErrEntryNotFound, sb.String())
}

// PatternError represents an error that occurred during pattern parsing.
// It contains the pattern, and the position of the offending segment.
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

// PanicError reports that a handler panicked.
type PanicError struct {
	Value any
	Stack string
}

func (e *PanicError) Error() string { return fmt.Sprintf("handler panic: %v", e.Value) }

func (e *PanicError) Unwrap() error {
	err, _ := e.Value.(error)
	return err
}

const (
	// panicStackFrames bounds what a capture costs.
	panicStackFrames = 16
	// panicStackSkip drops runtime.Callers, stacktrace, the deferred closure and
	// runtime.gopanic, so the first frame reported is the one that panicked.
	panicStackSkip = 3
)

// stacktrace formats the call stack of its caller, dropping the first skip frames and keeping
// at most panicStackFrames of what is left.
func stacktrace(skip int) string {
	pcs := make([]uintptr, panicStackFrames)
	n := runtime.Callers(skip+1, pcs)
	if n == 0 {
		return ""
	}

	var sb strings.Builder
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		sb.WriteString(frame.Function)
		sb.WriteString("\n\t")
		sb.WriteString(frame.File)
		sb.WriteByte(':')
		sb.WriteString(strconv.Itoa(frame.Line))
		if !more {
			break
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}
