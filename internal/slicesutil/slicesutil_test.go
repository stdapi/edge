// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package slicesutil

import "testing"

func TestEqualUnsorted(t *testing.T) {
	cases := []struct {
		name   string
		s1, s2 []int
		want   bool
	}{
		{name: "both empty", want: true},
		{name: "same order", s1: []int{1, 2, 3}, s2: []int{1, 2, 3}, want: true},
		{name: "other order", s1: []int{3, 1, 2}, s2: []int{1, 2, 3}, want: true},
		{name: "different lengths", s1: []int{1, 2}, s2: []int{1, 2, 3}},
		{name: "duplicates are counted", s1: []int{1, 1, 2}, s2: []int{1, 2, 2}},
		{name: "same duplicates", s1: []int{1, 1, 2}, s2: []int{2, 1, 1}, want: true},
		{name: "disjoint", s1: []int{1}, s2: []int{2}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EqualUnsorted(tc.s1, tc.s2); got != tc.want {
				t.Fatalf("EqualUnsorted(%v, %v) = %v, want %v", tc.s1, tc.s2, got, tc.want)
			}
		})
	}
}

func TestOverlap(t *testing.T) {
	cases := []struct {
		name   string
		s1, s2 []string
		want   bool
	}{
		{name: "both empty", want: true},
		{name: "one empty", s1: []string{"GET"}},
		{name: "common element", s1: []string{"GET", "POST"}, s2: []string{"POST", "PUT"}, want: true},
		{name: "disjoint", s1: []string{"GET"}, s2: []string{"POST"}},
		{name: "first element in common", s1: []string{"DELETE", "GET"}, s2: []string{"DELETE"}, want: true},
		{name: "last element in common", s1: []string{"GET", "PUT"}, s2: []string{"POST", "PUT"}, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Overlap(tc.s1, tc.s2); got != tc.want {
				t.Fatalf("Overlap(%v, %v) = %v, want %v", tc.s1, tc.s2, got, tc.want)
			}
		})
	}
}
