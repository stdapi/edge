// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stdapi/edge/internal/iterutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func addGitHubAPI(t *testing.T, txn *Txn, host string) {
	t.Helper()
	for _, r := range githubAPI {
		_, err := txn.Add(host+r.path, noopHandler, WithMethods[HTTP](r.method), WithName[HTTP](r.method+":"+host+r.path))
		require.NoError(t, err)
	}
}

func TestTxn_Truncate(t *testing.T) {
	p := testProxy(t)
	require.NoError(t, p.Updates(func(txn *Txn) error {
		addGitHubAPI(t, txn, "api.github.test")
		return nil
	}))
	p.MustAdd[TCP]("smtp.test:25", noopStream)
	p.MustAdd[UDP]("[10.0.0.0/8]:53", forwardDatagram)

	txn := p.Txn(true)
	defer txn.Abort()
	require.NoError(t, txn.Truncate())
	assert.Zero(t, txn.Len())
	assert.Zero(t, iterutil.Len(txn.Iter().All()))
	assert.Equal(t, len(githubAPI)+2, p.Len(), "a truncate is not visible before the commit")

	before := p.Txn(false)
	defer before.Abort()
	txn.Commit()

	assertEmptyTree(t, p)
	assert.Zero(t, iterutil.Len(p.Iter().Names()))
	assert.False(t, p.Admits(target("api.github.test:443"), KindHTTP))
	assert.Equal(t, len(githubAPI)+2, before.Len())
	assert.Equal(t, len(githubAPI)+2, iterutil.Len(before.Iter().All()))
	assert.Equal(t, len(githubAPI), iterutil.Len(before.Iter().Names()))
	assert.True(t, before.Admits(target("api.github.test:443"), KindHTTP))
}

func TestTxn_Isolation(t *testing.T) {
	t.Run("iterator does not observe writes made after it", func(t *testing.T) {
		p := testProxy(t)
		require.NoError(t, p.Updates(func(txn *Txn) error {
			for _, pattern := range []string{"a.test/ab", "a.test/ab/cd", "a.test/ab/cd/ef"} {
				if _, err := txn.Add(pattern, noopHandler); err != nil {
					return err
				}
			}
			it := txn.Iter()

			var patterns []string
			for e := range it.All() {
				patterns = append(patterns, e.Pattern())
				for _, pattern := range []string{"a.test/ab/cd/ef/gh", "a.test/ab/cd/ef/gh/ij", "a.test/ab/cd/e", "a.test/ax", "b.test/ab"} {
					_, _ = txn.Add(pattern, noopHandler, WithName[HTTP](pattern))
				}
				_, _ = txn.Delete[HTTP]("a.test/ab/cd")
			}
			assert.Equal(t, []string{"a.test/ab", "a.test/ab/cd", "a.test/ab/cd/ef"}, patterns)
			assert.Equal(t, []string{"a.test/ab", "a.test/ab/cd", "a.test/ab/cd/ef"}, patternsOf(it.All()))
			assert.Equal(t, []string{"a.test"}, patternsOf(it.Admissions()))
			assert.Empty(t, patternsOf(it.Names()))
			assert.Equal(t, 7, iterutil.Len(txn.Iter().All()))
			return nil
		}))
	})

	t.Run("snapshot does not observe further writes", func(t *testing.T) {
		p := testProxy(t)
		require.NoError(t, p.Updates(func(txn *Txn) error {
			addGitHubAPI(t, txn, "api.github.test")
			snapshot := txn.Snapshot()
			addGitHubAPI(t, txn, "mirror.github.test")

			const pattern = "mirror.github.test/repos/{owner}/{repo}/comments"
			assert.False(t, snapshot.Has[HTTP](pattern, mustMethods(http.MethodGet)))
			_, ok := snapshot.Named[HTTP]("GET:" + pattern)
			assert.False(t, ok)
			assert.False(t, snapshot.Admits(target("mirror.github.test:443"), KindHTTP))

			assert.True(t, txn.Has[HTTP](pattern, mustMethods(http.MethodGet)))
			_, ok = txn.Named[HTTP]("GET:" + pattern)
			assert.True(t, ok)
			assert.True(t, txn.Admits(target("mirror.github.test:443"), KindHTTP))
			return nil
		}))
	})

	t.Run("read transaction does not observe writes", func(t *testing.T) {
		p := testProxy(t)
		require.NoError(t, p.Updates(func(txn *Txn) error {
			addGitHubAPI(t, txn, "api.github.test")
			return nil
		}))

		const pattern = "mirror.github.test/repos/{owner}/{repo}/comments"
		require.NoError(t, p.View(func(txn *Txn) error {
			require.NoError(t, p.Updates(func(txn *Txn) error {
				addGitHubAPI(t, txn, "mirror.github.test")
				return nil
			}))
			assert.Equal(t, len(githubAPI), txn.Len())
			assert.Equal(t, len(githubAPI), iterutil.Len(txn.Iter().All()))
			assert.Equal(t, len(githubAPI), iterutil.Len(txn.Iter().Names()))
			assert.False(t, txn.Has[HTTP](pattern, mustMethods(http.MethodGet)))
			_, ok := txn.Named[HTTP]("GET:" + pattern)
			assert.False(t, ok)
			assert.True(t, p.Has[HTTP](pattern, mustMethods(http.MethodGet)))
			return nil
		}))
		assert.Equal(t, 2*len(githubAPI), iterutil.Len(p.Iter().All()))
	})

	t.Run("read transactions run uncoordinated", func(t *testing.T) {
		p := testProxy(t)
		first := p.Txn(false)
		defer first.Abort()
		p.MustAdd("a.test/foo", noopHandler)
		second := p.Txn(false)
		defer second.Abort()

		assert.Zero(t, first.Len())
		assert.Equal(t, 1, second.Len())
	})

	t.Run("failed update writes nothing", func(t *testing.T) {
		p := testProxy(t)
		p.MustAdd("a.test/foo", noopHandler, WithName[HTTP]("foo"))

		want := errors.New("abort")
		err := p.Updates(func(txn *Txn) error {
			addGitHubAPI(t, txn, "api.github.test")
			_, err := txn.Delete[HTTP]("a.test/foo")
			require.NoError(t, err)
			assert.Equal(t, len(githubAPI), txn.Len())
			return want
		})
		require.ErrorIs(t, err, want)
		assert.Equal(t, 1, p.Len())
		assert.Equal(t, 1, iterutil.Len(p.Iter().Names()))
		assert.False(t, p.Admits(target("api.github.test:443"), KindHTTP))
	})

	t.Run("panicking update writes nothing", func(t *testing.T) {
		p := testProxy(t)
		assert.Panics(t, func() {
			_ = p.Updates(func(txn *Txn) error {
				addGitHubAPI(t, txn, "api.github.test")
				panic("abort")
			})
		})
		assertEmptyTree(t, p)
		p.MustAdd("a.test/foo", noopHandler)
	})

	t.Run("length follows adds and deletes", func(t *testing.T) {
		p := testProxy(t)
		require.NoError(t, p.Updates(func(txn *Txn) error {
			addGitHubAPI(t, txn, "api.github.test")
			assert.Equal(t, len(githubAPI), txn.Len())
			for _, r := range githubAPI {
				if _, err := txn.Delete[HTTP]("api.github.test"+r.path, WithMethods[HTTP](r.method)); err != nil {
					return err
				}
			}
			assert.Zero(t, txn.Len())
			return nil
		}))
		assertEmptyTree(t, p)
	})
}

func TestTxn_WriteOnReadTransaction(t *testing.T) {
	p := testProxy(t)
	txn := p.Txn(false)
	defer txn.Abort()

	_, err := txn.Add("a.test/foo", noopHandler)
	assert.ErrorIs(t, err, ErrReadOnlyTxn)
	_, err = txn.Update("a.test/foo", noopHandler)
	assert.ErrorIs(t, err, ErrReadOnlyTxn)
	_, err = txn.Delete[HTTP]("a.test/foo")
	assert.ErrorIs(t, err, ErrReadOnlyTxn)
	assert.ErrorIs(t, txn.Truncate(), ErrReadOnlyTxn)
	txn.Commit()
}

func TestTxn_UseAfterAbort(t *testing.T) {
	p := testProxy(t)
	txn := p.Txn(true)
	txn.Abort()

	for name, fn := range map[string]func(){
		"Add":      func() { _, _ = txn.Add("a.test/foo", noopHandler) },
		"Update":   func() { _, _ = txn.Update("a.test/foo", noopHandler) },
		"Delete":   func() { _, _ = txn.Delete[HTTP]("a.test/foo") },
		"Has":      func() { txn.Has[HTTP]("a.test/foo") },
		"Lookup":   func() { _, _ = txn.Lookup[HTTP]("a.test/foo") },
		"Named":    func() { _, _ = txn.Named[HTTP]("foo") },
		"Truncate": func() { _ = txn.Truncate() },
		"Admits":   func() { txn.Admits(target("a.test:443"), KindHTTP) },
		"Iter":     func() { txn.Iter() },
	} {
		assert.PanicsWithValue(t, ErrSettledTxn, fn, name)
	}
	assert.NotPanics(t, func() {
		txn.Commit()
		txn.Abort()
	})
	assert.Nil(t, txn.Snapshot())
}

func TestTxn_AddConflictWritesNothing(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))
	v1, err := MatchQuery("version", "v1")
	require.NoError(t, err)
	v2, err := MatchQuery("version", "v2")
	require.NoError(t, err)
	secret, err := MatchHeader("Authorization", "secret")
	require.NoError(t, err)

	p.MustAdd("a.test/users", noopHandler, WithRequestMatchers[HTTP](v1, secret), WithName[HTTP]("users"))
	p.MustAdd("a.test/users/{name}", noopHandler, WithRequestMatchers[HTTP](v2, secret), WithName[HTTP]("users_name"))
	p.MustAdd("example.test/users/{name}", noopHandler, WithRequestMatchers[HTTP](v2, secret), WithName[HTTP]("hostname_users_name"))

	cases := []struct {
		name    string
		pattern string
		opts    []EntryOption[HTTP]
		err     any
	}{
		{"same matchers", "a.test/users/{id}", []EntryOption[HTTP]{WithRequestMatchers[HTTP](v2, secret)}, new(*EntryConflictError)},
		{"name of another pattern", "a.test/users/{id}", []EntryOption[HTTP]{WithRequestMatchers[HTTP](v1, secret), WithName[HTTP]("users")}, new(*EntryNameConflictError)},
		{"name of a param pattern", "a.test/users/{id}", []EntryOption[HTTP]{WithRequestMatchers[HTTP](v1, secret), WithName[HTTP]("users_name")}, new(*EntryNameConflictError)},
		{"name on a split node", "a.test/use", []EntryOption[HTTP]{WithName[HTTP]("users_name")}, new(*EntryNameConflictError)},
		{"name on a sibling node", "a.test/usa", []EntryOption[HTTP]{WithName[HTTP]("users_name")}, new(*EntryNameConflictError)},
		{"name on a new branch", "a.test/usa/foo", []EntryOption[HTTP]{WithName[HTTP]("users_name")}, new(*EntryNameConflictError)},
		{"name below a param", "a.test/users/{name}/email", []EntryOption[HTTP]{WithName[HTTP]("users_name")}, new(*EntryNameConflictError)},
		{"name on a regexp param", "a.test/users/{name:aaa}", []EntryOption[HTTP]{WithName[HTTP]("users_name")}, new(*EntryNameConflictError)},
		{"name on another hostname", "example.test/use", []EntryOption[HTTP]{WithName[HTTP]("users")}, new(*EntryNameConflictError)},
		{"name on a new hostname", "fresh.test/users", []EntryOption[HTTP]{WithName[HTTP]("users")}, new(*EntryNameConflictError)},
	}

	txn := p.Txn(true)
	defer txn.Abort()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := txn.Add(tc.pattern, noopHandler, tc.opts...)
			require.ErrorAs(t, err, tc.err)
			assert.Nil(t, txn.rootTxn.writable, "a refused add copies no node")
		})
	}
	txn.Commit()

	assert.Equal(t, 3, p.Len())
	assert.False(t, p.Admits(target("fresh.test:443"), KindHTTP))
	for _, tc := range cases {
		assert.False(t, p.Has[HTTP](tc.pattern), tc.pattern)
	}
}

func TestTxn_UpdateWithName(t *testing.T) {
	v1, err := MatchQuery("version", "v1")
	require.NoError(t, err)
	v2, err := MatchQuery("version", "v2")
	require.NoError(t, err)
	v3, err := MatchQuery("version", "v3")
	require.NoError(t, err)
	secret, err := MatchHeader("Authorization", "secret")
	require.NoError(t, err)

	setup := func(t *testing.T) *Proxy {
		p := testProxy(t)
		p.MustAdd("a.test/users", noopHandler)
		p.MustAdd("a.test/users", noopHandler, WithRequestMatchers[HTTP](v1, secret), WithName[HTTP]("users"))
		p.MustAdd("a.test/users/{name}", noopHandler, WithRequestMatchers[HTTP](v2, secret), WithName[HTTP]("users_name"))
		return p
	}

	t.Run("refused", func(t *testing.T) {
		p := setup(t)
		txn := p.Txn(true)
		defer txn.Abort()

		_, err := txn.Update("a.test/users/{name}", noopHandler, WithRequestMatchers[HTTP](v3, secret))
		assert.ErrorIs(t, err, ErrEntryNotFound, "other matchers")
		assert.Nil(t, txn.rootTxn.writable)

		_, err = txn.Update("a.test/users/{id}", noopHandler, WithRequestMatchers[HTTP](v2, secret))
		assert.ErrorIs(t, err, ErrEntryNotFound, "other param key")
		assert.Nil(t, txn.rootTxn.writable)

		_, err = txn.Update("a.test/users", noopHandler, WithName[HTTP]("users"))
		assert.ErrorAs(t, err, new(*EntryNameConflictError), "name added")
		assert.Nil(t, txn.rootTxn.writable)

		_, err = txn.Update("a.test/users", noopHandler, WithRequestMatchers[HTTP](v1, secret), WithName[HTTP]("users_name"))
		assert.ErrorAs(t, err, new(*EntryNameConflictError), "name replaced")
		assert.Nil(t, txn.rootTxn.writable)
	})

	t.Run("name dropped", func(t *testing.T) {
		p := setup(t)
		require.NoError(t, p.Updates(func(txn *Txn) error {
			e, err := txn.Update("a.test/users/{name}", noopHandler, WithRequestMatchers[HTTP](v2, secret))
			require.NoError(t, err)
			assert.Empty(t, e.Name())
			_, ok := txn.Named[HTTP]("users_name")
			assert.False(t, ok)
			return nil
		}))
		_, ok := p.Named[HTTP]("users_name")
		assert.False(t, ok)
	})

	t.Run("name added", func(t *testing.T) {
		p := setup(t)
		require.NoError(t, p.Updates(func(txn *Txn) error {
			e, err := txn.Update("a.test/users", noopHandler, WithName[HTTP]("foo"))
			require.NoError(t, err)
			assert.Equal(t, "foo", e.Name())
			return nil
		}))
		e, ok := p.Named[HTTP]("foo")
		require.True(t, ok)
		assert.Equal(t, "a.test/users", e.Pattern())
		assert.Zero(t, iterutil.Len(e.RequestMatchers()))
	})

	t.Run("name kept", func(t *testing.T) {
		p := setup(t)
		_, err := p.Update("a.test/users", noopHandler, WithRequestMatchers[HTTP](v1, secret), WithName[HTTP]("users"))
		require.NoError(t, err)
		_, ok := p.Named[HTTP]("users")
		assert.True(t, ok)
	})

	t.Run("name replaced", func(t *testing.T) {
		p := setup(t)
		_, err := p.Update("a.test/users", noopHandler, WithRequestMatchers[HTTP](v1, secret), WithName[HTTP]("new_users"))
		require.NoError(t, err)
		_, ok := p.Named[HTTP]("users")
		assert.False(t, ok)
		_, ok = p.Named[HTTP]("new_users")
		assert.True(t, ok)
	})
}
