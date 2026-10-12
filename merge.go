// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"io"
	"sync"
)

// errSourcesEnded is the cancel cause of a context once both sources of a merge ended. A read
// of either source then returns without blocking.
var errSourcesEnded = errors.New("edge: connection ended")

// merged interleaves two sources for one consumer. A source that returns io.EOF is done and
// the other is still read. The merge returns io.EOF once both sources are done, and any other
// error as soon as a source returns it.
//
// Each source runs on its own goroutine and is read again only after the consumer has asked
// for the next unit, which keeps the unit it delivered valid until then. ctx must end with the
// handler, since a pump blocked on a unit the consumer never asks for exits on it.
//
// Once ctx ends the merge returns its error. If both sources share ctx and the cause is
// errSourcesEnded, it reads them to their end.
type merged[T any] struct {
	ctx        context.Context
	a, b       func() (T, error)
	own        func() (T, error)
	ch         chan uint8
	pendingAck chan struct{}
	err        error
	src        [2]mergedSource[T]
	done       int
	once       sync.Once
	apart      bool
}

// mergedSource is written by its pump before the index of the source is sent on ch.
type mergedSource[T any] struct {
	v   T
	err error
	ack chan struct{}
}

const mergedStopped = 2

func (m *merged[T]) pump(i uint8) {
	s := &m.src[i]
	read := m.source(i)
	for {
		v, err := read()
		s.v, s.err = v, err
		// ch has room for two indices per pump, so a send never blocks.
		m.ch <- i
		if err != nil {
			return
		}
		select {
		case <-s.ack:
		case <-m.ctx.Done():
			m.ch <- i | mergedStopped
			return
		}
	}
}

func (m *merged[T]) read() (T, error) {
	var zero T
	m.once.Do(func() {
		m.ch = make(chan uint8, 4)
		m.src[0].ack = make(chan struct{}, 1)
		m.src[1].ack = make(chan struct{}, 1)
		go m.pump(0)
		go m.pump(1)
	})

	if m.pendingAck != nil {
		m.pendingAck <- struct{}{}
		m.pendingAck = nil
	}

	for m.done < 2 && m.err == nil {
		var v T
		var err error
		if m.own != nil {
			v, err = m.own()
			if err != nil {
				m.own = nil
			}
		} else {
			var i uint8
			select {
			case i = <-m.ch:
			case <-m.ctx.Done():
				if m.sourcesEnded() {
					i = <-m.ch
				} else {
					select {
					case i = <-m.ch:
					default:
						return zero, m.ctx.Err()
					}
				}
			}
			if i&mergedStopped != 0 {
				if m.sourcesEnded() {
					m.own = m.source(i &^ mergedStopped)
				}
				continue
			}
			s := &m.src[i]
			v, err = s.v, s.err
			if err == nil {
				m.pendingAck = s.ack
			}
		}

		if err == nil {
			return v, nil
		}
		m.done++
		if !errors.Is(err, io.EOF) {
			m.err = err
		}
	}
	if m.err != nil {
		return zero, m.err
	}
	return zero, io.EOF
}

func (m *merged[T]) source(i uint8) func() (T, error) {
	if i == 0 {
		return m.a
	}
	return m.b
}

func (m *merged[T]) sourcesEnded() bool {
	return !m.apart && errors.Is(context.Cause(m.ctx), errSourcesEnded)
}
