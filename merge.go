// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"io"
	"sync"
)

// merged interleaves two sources for one consumer. A source that returns io.EOF is done and
// the other is still read. The merge returns io.EOF once both sources are done, and any other
// error as soon as a source returns it.
//
// Each source runs on its own goroutine and is read again only after the consumer has asked
// for the next unit, which keeps the unit it delivered valid until then. ctx must end with the
// handler, since a pump blocked on a unit the consumer never asks for exits on it.
type merged[T any] struct {
	ctx        context.Context
	a, b       func() (T, error)
	ch         chan mergedItem[T]
	pendingAck chan struct{}
	err        error
	once       sync.Once
	done       int
}

type mergedItem[T any] struct {
	v   T
	err error
	ack chan struct{}
}

func (m *merged[T]) pump(read func() (T, error)) {
	ack := make(chan struct{})
	for {
		v, err := read()
		select {
		case m.ch <- mergedItem[T]{v: v, err: err, ack: ack}:
		case <-m.ctx.Done():
			return
		}
		if err != nil {
			return
		}
		select {
		case <-ack:
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *merged[T]) read() (T, error) {
	var zero T
	m.once.Do(func() {
		m.ch = make(chan mergedItem[T])
		go m.pump(m.a)
		go m.pump(m.b)
	})

	if m.pendingAck != nil {
		select {
		case m.pendingAck <- struct{}{}:
		case <-m.ctx.Done():
			return zero, m.ctx.Err()
		}
		m.pendingAck = nil
	}

	for m.done < 2 && m.err == nil {
		select {
		case it := <-m.ch:
			if it.err == nil {
				m.pendingAck = it.ack
				return it.v, nil
			}
			m.done++
			if !errors.Is(it.err, io.EOF) {
				m.err = it.err
			}
		case <-m.ctx.Done():
			return zero, m.ctx.Err()
		}
	}
	if m.err != nil {
		return zero, m.err
	}
	return zero, io.EOF
}
