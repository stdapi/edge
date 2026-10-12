package edge

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/stdapi/edge/internal/stringsutil"
)

type node struct {
	// entries holds the registered handlers if this node is a leaf.
	entries []*entry

	// regexp is an optional compiled regular expression constraint for param and wildcard nodes.
	// When present, captured segments must match this pattern during lookup.
	regexp *regexp.Regexp

	// key identifies the node's content and varies by node type:
	//
	// Static nodes: Contains the literal path segment (e.g., "/users", "foo")
	//
	// Param nodes without regex: Contains "?" as a canonical placeholder.
	// This allows interceptors with different param names (/foo/{bar} and /foo/{fizz})
	// to share the same tree node while preventing duplicate registration.
	// The actual placeholder names are stored in the interceptor definition.
	//
	// Wildcard nodes without regex: Contains "*" as a canonical placeholder,
	// following the same sharing semantics as params.
	//
	// Param/wildcard nodes with regex contains the regex pattern literal.
	// Multiple regex nodes can exist at the same level, each with a distinct pattern.
	// During lookup, patterns are evaluated in insertion order until one matches.
	key string

	// statics contains child nodes for static path segments, sorted by label byte.
	statics []*node

	// params contains child nodes for parameters. Regex params are ordered first
	// (in insertion order), followed by at most one non-regex param node ("?").
	params []*node

	// wildcards contains child nodes for catch-all segments. Regex wildcards are
	// ordered first (in insertion order), followed by at most one non-regex wildcard ("*").
	wildcards []*node

	// label is the first byte of the key for static nodes, used for binary search.
	// Set to 0x00 for param and wildcard nodes.
	label byte

	// host indicates this node's key belongs to the hostname portion of the interceptor.
	// A node that belong to a host cannot be merged with a child key that start with a '/'.
	host bool
}

// lookupByAddr resolves key, the encoded address of a target, against the address root. The
// walk is a longest-prefix match: every node the key fully covers is a candidate, the
// deepest answers first, and a refusal falls back to the next shorter prefix. With admit set
// a candidate answers through the entry admitting that kind, otherwise through the path
// subtree under its '/' edge.
//
// A registered prefix always ends on a node boundary. The insert splits nodes to attach its
// entries or its path subtree, and a delete never merges a node that still carries either,
// which is what lets the walk test candidacy only where a child key was consumed whole.
func lookupByAddr(root *node, key []byte, path string, c *routeCtx, lazy bool, admit Kind) (int, *node) {
	// One slot per consumed-key position, the root included even though it can never
	// qualify today, so a new candidate class cannot overflow the array.
	var cands [maxAddrKey + 1]*node
	n := 0

	matched := root
	search := key
	for {
		if admit != 0 {
			if matched.isLeaf() {
				cands[n] = matched
				n++
			}
		} else if _, pathChild := matched.getStaticEdge(slashDelim); pathChild != nil {
			cands[n] = matched
			n++
		}
		if len(search) == 0 {
			break
		}
		_, child := matched.getStaticEdge(search[0])
		if child == nil {
			break
		}
		keyLen := len(child.key)
		if keyLen > len(search) || string(search[:keyLen]) != child.key {
			break
		}
		matched = child
		search = search[keyLen:]
	}

	for i := n - 1; i >= 0; i-- {
		cand := cands[i]
		if admit != 0 {
			if idx, ok := findAdmission(cand, c, admit); ok {
				return idx, cand
			}
			continue
		}
		paramCnt := len(*c.params)
		if idx, subNode := lookupByPath(cand, path, c, lazy, 0); subNode != nil {
			return idx, subNode
		}
		*c.skipStack = (*c.skipStack)[:0]
		*c.params = (*c.params)[:paramCnt]
	}
	return 0, nil
}

// lookupByHostname walks the hostname portion of the key. With admit set it stops there and
// answers with the entry sitting on the node the hostname ended on, instead of descending
// into the path. An admission key carries no path at all, which is what keeps the two kinds
// of entry from ever reaching each other.
func lookupByHostname(root *node, host, path string, c *routeCtx, lazy bool, admit Kind) (index int, n *node) {
	var (
		charsMatched     int
		skipStatic       bool
		childParamIdx    int
		childWildcardIdx int
		wildcardOffset   int
	)

	matched := root
	search := host

Walk:
	for len(search) > 0 {
		if !skipStatic {
			label := stringsutil.ToLowerASCII(search[0])
			num := len(matched.statics)
			idx := sort.Search(num, func(i int) bool { return matched.statics[i].label >= label })
			if idx < num && matched.statics[idx].label == label {
				child := matched.statics[idx]
				keyLen := len(child.key)
				// keyLen == 1 short-circuits the case-insensitive compare: hostname keys are
				// stored lowercase (uppercase is rejected at parse time) and the label match
				// already proved lowercase(search[0]) == child.key[0].
				if keyLen == 1 || (keyLen <= len(search) && stringsutil.EqualStringsASCIIIgnoreCase(search[:keyLen], child.key)) {
					if len(matched.params) > 0 || len(matched.wildcards) > 0 {
						*c.skipStack = append(*c.skipStack, skipNode{
							node:         matched,
							charsMatched: charsMatched,
							paramCnt:     len(*c.params),
						})
					}

					matched = child
					search = search[keyLen:]
					charsMatched += keyLen
					continue
				}
			}
		}

		skipStatic = false
		params := matched.params[childParamIdx:]
		if len(params) > 0 {
			end := strings.IndexByte(search, dotDelim)
			if end == -1 {
				end = len(search)
			}

			hasWildcards := len(matched.wildcards) > 0
			if end == 0 {
				if hasWildcards {
					*c.skipStack = append(*c.skipStack, skipNode{
						node:          matched,
						charsMatched:  charsMatched,
						paramCnt:      len(*c.params),
						childParamIdx: len(matched.params),
					})
				}
				goto Backtrack
			}

			segment := search[:end]
			for i, paramNode := range params {
				if paramNode.regexp != nil && !paramNode.regexp.MatchString(segment) {
					continue
				}

				nextChildIx := i + 1
				if nextChildIx < len(params) || hasWildcards {
					*c.skipStack = append(*c.skipStack, skipNode{
						node:          matched,
						charsMatched:  charsMatched,
						paramCnt:      len(*c.params),
						childParamIdx: nextChildIx + childParamIdx,
					})
				}

				if !lazy {
					*c.params = append(*c.params, segment)
				}

				matched = paramNode
				search = search[end:]
				charsMatched += end
				childParamIdx = 0
				goto Walk
			}
		}

		wildcards := matched.wildcards[childWildcardIdx:]
		if len(wildcards) > 0 {
			offset := charsMatched
			// Try infix wildcards first
			for i, wildcardNode := range wildcards {
				if len(wildcardNode.statics) == 1 && wildcardNode.statics[0].label == slashDelim {
					continue // Not an infix wildcard
				}

				// Start searching from the wildcard's base position + any accumulated offset from last
				// node put in the skip stack.
				searchStart := charsMatched + wildcardOffset
				for {
					// Search for next dot from current offset
					idx := strings.IndexByte(host[searchStart:], dotDelim)
					if idx < 0 {
						break
					}

					captureEnd := searchStart + idx
					capturedValue := host[charsMatched:captureEnd]

					// Skip empty captures (consecutive dot)
					if capturedValue == "" {
						searchStart++
						continue
					}

					if wildcardNode.regexp != nil && !wildcardNode.regexp.MatchString(capturedValue) {
						searchStart = captureEnd + 1
						continue
					}

					// We have a potential match, save backtrack state
					// The next attempt should search starting one position after current searchStart
					*c.skipStack = append(*c.skipStack, skipNode{
						node:             matched,
						charsMatched:     charsMatched,
						paramCnt:         len(*c.params),
						childParamIdx:    len(matched.params),
						childWildcardIdx: i + childWildcardIdx,
						wildcardOffset:   captureEnd - charsMatched + 1,
					})

					if !lazy {
						*c.params = append(*c.params, capturedValue)
					}

					// Descend into wildcard subtree
					matched = wildcardNode
					search = host[captureEnd:]
					charsMatched = captureEnd
					childParamIdx = 0
					childWildcardIdx = 0
					wildcardOffset = 0
					goto Walk
				}

				nextChildIdx := i + 1
				if nextChildIdx < len(wildcards) {
					*c.skipStack = append(*c.skipStack, skipNode{
						node:             matched,
						charsMatched:     offset,
						paramCnt:         len(*c.params),
						childParamIdx:    len(matched.params),
						childWildcardIdx: nextChildIdx + childWildcardIdx,
						wildcardOffset:   0, // Next wildcard starts from beginning
					})
					goto Backtrack
				}
			}

			// After trying all infix wildcards, try suffix catchalls. The path is
			// matched in place so a failed candidate does not end the lookup.
			for _, wildcardNode := range matched.wildcards {
				if len(wildcardNode.statics) == 1 && wildcardNode.statics[0].label == dotDelim {
					continue // Not a suffix catchall
				}

				if wildcardNode.regexp != nil && !wildcardNode.regexp.MatchString(search) {
					continue
				}

				paramCnt := len(*c.params)
				if !lazy {
					*c.params = append(*c.params, search)
				}

				if admit != 0 {
					if i, ok := findAdmission(wildcardNode, c, admit); ok {
						return i, wildcardNode
					}
					*c.params = (*c.params)[:paramCnt]
					continue
				}

				stackOffset := len(*c.skipStack)
				if idx, subNode := lookupByPath(wildcardNode, path, c, lazy, stackOffset); subNode != nil {
					return idx, subNode
				}

				*c.skipStack = (*c.skipStack)[:stackOffset]
				*c.params = (*c.params)[:paramCnt]
			}
		}

		goto Backtrack
	}

	if admit != 0 {
		if i, ok := findAdmission(matched, c, admit); ok {
			return i, matched
		}
	} else if _, pathChild := matched.getStaticEdge(slashDelim); pathChild != nil {
		stackOffset := len(*c.skipStack)
		idx, subNode := lookupByPath(matched, path, c, lazy, stackOffset)
		if subNode != nil {
			return idx, subNode
		}

		// Remove any unused skip nodes added during the path lookup.
		*c.skipStack = (*c.skipStack)[:stackOffset]
	}

Backtrack:
	if len(*c.skipStack) == 0 {
		return
	}

	// A skip node pushed with params left to try is always pushed with childWildcardIdx
	// and wildcardOffset at zero, so restoring every field as saved is correct in all cases.
	skipped := c.skipStack.pop()

	matched = skipped.node
	*c.params = (*c.params)[:skipped.paramCnt]
	search = host[skipped.charsMatched:]
	charsMatched = skipped.charsMatched
	childParamIdx = skipped.childParamIdx
	childWildcardIdx = skipped.childWildcardIdx
	wildcardOffset = skipped.wildcardOffset
	skipStatic = true

	goto Walk
}

// lookupByPath returns the node matching path, or nil when nothing matches. An interceptor
// with a relaxed slash also matches the path with its trailing slash added or removed, and one
// with an exact slash is never a candidate for that. The request is forwarded as the client
// sent it either way, so nothing outside this walk depends on which form matched.
//
// A slash candidate counts as a direct match and keeps the priority of the branch where it was
// found (static > regex param > param > regex wildcard > wildcard). The lookup returns it
// without exploring lower priority alternatives on the skip stack, even when one of them
// matches the path exactly. For example with /foo/ registered with a relaxed slash and /{a}, a
// request for /foo matches /foo/ because the static branch has priority over the param branch.
//
// When both slash variants of the same pattern are registered, each request form is served by
// its exact variant. Static and param patterns need no special handling since the exact leaf
// is checked before any slash candidate. Catch-alls need special handling because the infix
// wildcard (/+{x}/) is always walked before the suffix (/+{x}) to favor the longest match,
// otherwise the suffix would always win as it matches any remainder. The infix candidate is
// recorded and only used when no suffix catch-all at the same node matches directly.
//
// A slash candidate never crosses a "//" boundary, so /foo// and /foo/ stay distinct.
func lookupByPath(root *node, path string, c *routeCtx, lazy bool, stackOffset int) (index int, n *node) {

	var (
		charsMatched     int
		skipStatic       bool
		childParamIdx    int
		childWildcardIdx int
		wildcardOffset   int
		parent           *node
		deferredSlash    bool
	)

	matched := root
	search := path

Walk:
	for len(search) > 0 {
		if !skipStatic {
			label := search[0]
			num := len(matched.statics)
			idx := sort.Search(num, func(i int) bool { return matched.statics[i].label >= label })
			if idx < num && matched.statics[idx].label == label {
				child := matched.statics[idx]
				keyLen := len(child.key)
				// While this is less performant than byte-by-byte comparaison for reasonable search size,
				// direct == comparaison on string scale way better on long keys. The keyLen == 1 case
				// short-circuits the memequal call: we already verified search[0] == child.key[0] via the
				// label match above.
				if keyLen == 1 || (keyLen <= len(search) && search[:keyLen] == child.key) {
					// Only the lookup root can have hostname params and wildcards.
					// A path lookup must skip them.
					if (len(matched.params) > 0 || len(matched.wildcards) > 0) && matched != root {
						*c.skipStack = append(*c.skipStack, skipNode{
							node:         matched,
							parent:       parent,
							charsMatched: charsMatched,
							paramCnt:     len(*c.params),
						})
					}

					parent = matched
					matched = child
					search = search[keyLen:]
					charsMatched += keyLen
					continue
				}

				// Child key is exactly search plus a trailing slash (e.g. search /foo, key /foo/),
				// excluding keys ending in "//". The length check keeps the common mismatch cheap.
				if keyLen == len(search)+1 && child.key[keyLen-1] == '/' && child.key[keyLen-2] != '/' && strings.HasPrefix(child.key, search) {
					if i, slashNode := matchTrailingSlash(child, c, lazy); slashNode != nil {
						return i, slashNode
					}
				}
			}
		}

		skipStatic = false
		params := matched.params[childParamIdx:]
		if len(params) > 0 && matched != root {
			end := strings.IndexByte(search, slashDelim)
			if end == -1 {
				end = len(search)
			}

			hasWildcards := len(matched.wildcards) > 0
			if end == 0 {
				if hasWildcards {
					*c.skipStack = append(*c.skipStack, skipNode{
						node:          matched,
						parent:        parent,
						charsMatched:  charsMatched,
						paramCnt:      len(*c.params),
						childParamIdx: len(matched.params),
					})
				}
				goto Backtrack
			}

			segment := search[:end]
			for i, paramNode := range params {
				if paramNode.regexp != nil && !paramNode.regexp.MatchString(segment) {
					continue
				}

				nextChildIx := i + 1
				if nextChildIx < len(params) || hasWildcards {
					*c.skipStack = append(*c.skipStack, skipNode{
						node:          matched,
						parent:        parent,
						charsMatched:  charsMatched,
						paramCnt:      len(*c.params),
						childParamIdx: nextChildIx + childParamIdx,
					})
				}

				if !lazy {
					*c.params = append(*c.params, segment)
				}

				parent = matched
				matched = paramNode
				search = search[end:]
				charsMatched += end
				childParamIdx = 0
				goto Walk
			}
		}

		wildcards := matched.wildcards[childWildcardIdx:]
		if len(wildcards) > 0 && matched != root {
			offset := charsMatched

		WalkWildcard:
			// Try infix wildcards first
			for i, wildcardNode := range wildcards {
				if len(wildcardNode.statics) == 0 {
					continue // Not an infix wildcard
				}

				// Start searching from the wildcard's base position + any accumulated offset from last
				// node put in the skip stack.
				searchStart := charsMatched + wildcardOffset

				for {
					// Search for next slash from current offset
					idx := strings.IndexByte(path[searchStart:], slashDelim)
					if idx < 0 {
						if len(path[searchStart:]) > 0 {
							if _, child := wildcardNode.getStaticEdge(slashDelim); child != nil && child.isLeaf() && child.key == "/" {
								// We have the path /foo/x/y/z for the interceptor /foo/+{any:[A-z]}/ that may be matched with a ts,
								// but we need to make sure that the regexp match too.
								if wildcardNode.regexp != nil && !wildcardNode.regexp.MatchString(path[offset:]) {
									break
								}
								for j, ic := range child.entries {
									if ic.relaxedSlash && ic.match(c) {
										// This is the only case where we don't return a slash match immediately. Interceptors
										// like /+{args}/ (relaxed slash) and /+{args} can coexist. For a request like
										// /a/b/c, the infix /+{args}/ would match with a trailing slash added, but we must
										// first check whether a suffix catch-all directly matches. We capture the node here
										// but defer parameter recording as a fallback.
										n = child
										deferredSlash = true
										index = j
										break WalkWildcard
									}
								}
							}
						}
						break
					}

					captureEnd := searchStart + idx
					capturedValue := path[charsMatched:captureEnd]

					// Skip empty captures (consecutive slashes)
					if capturedValue == "" {
						searchStart++
						continue
					}

					if wildcardNode.regexp != nil && !wildcardNode.regexp.MatchString(capturedValue) {
						searchStart = captureEnd + 1
						continue
					}

					// We have a potential match, save backtrack state
					// The next attempt should search starting one position after current searchStart
					*c.skipStack = append(*c.skipStack, skipNode{
						node:             matched,
						parent:           parent,
						charsMatched:     charsMatched,
						paramCnt:         len(*c.params),
						childParamIdx:    len(matched.params),
						childWildcardIdx: i + childWildcardIdx,
						wildcardOffset:   captureEnd - charsMatched + 1,
					})

					if !lazy {
						*c.params = append(*c.params, capturedValue)
					}

					// Descend into wildcard subtree
					parent = matched
					matched = wildcardNode
					search = path[captureEnd:]
					charsMatched = captureEnd
					childParamIdx = 0
					childWildcardIdx = 0
					wildcardOffset = 0
					goto Walk
				}

				nextChildIdx := i + 1
				if nextChildIdx < len(wildcards) {
					*c.skipStack = append(*c.skipStack, skipNode{
						node:             matched,
						parent:           parent,
						charsMatched:     offset,
						paramCnt:         len(*c.params),
						childParamIdx:    len(matched.params),
						childWildcardIdx: nextChildIdx + childWildcardIdx,
						wildcardOffset:   0, // Next wildcard starts from beginning
					})
					goto Backtrack
				}
			}

			// After trying all infix wildcards, try suffix catchalls
			for _, wildcardNode := range matched.wildcards {
				if !wildcardNode.isLeaf() {
					continue // Not a suffix catchall
				}

				if wildcardNode.regexp != nil && !wildcardNode.regexp.MatchString(search) {
					continue
				}

				for i, ic := range wildcardNode.entries {
					if ic.match(c) {
						if !lazy {
							*c.params = append(*c.params, search)
						}
						return i, wildcardNode
					}
				}
			}

			// fallback to the deferred slash candidate if any recorded
			if deferredSlash {
				if !lazy {
					*c.params = append(*c.params, path[offset:])
				}
				return
			}
		}

		goto Backtrack
	}

	if matched.isLeaf() {
		for i, ic := range matched.entries {
			if ic.match(c) {
				return i, matched
			}
		}
	}

	// Try to catch empty for wildcard supporting it.
	for _, wildcardNode := range matched.wildcards {
		for i, ic := range wildcardNode.entries {
			if ic.pattern.optionalCatchAll && ic.match(c) {
				if !lazy {
					*c.params = append(*c.params, "")
				}
				return i, wildcardNode
			}
		}
	}

	if _, child := matched.getStaticEdge(slashDelim); child != nil && child.key == "/" && !strings.HasSuffix(path, "/") {
		if i, slashNode := matchTrailingSlash(child, c, lazy); slashNode != nil {
			return i, slashNode
		}
	} else if matched.key == "/" && parent != nil && parent.isLeaf() && !strings.HasSuffix(path, "//") {
		for i, ic := range parent.entries {
			if ic.relaxedSlash && !ic.pattern.catchAll && ic.match(c) {
				return i, parent
			}
		}
	}

Backtrack:
	if search == "/" && matched.isLeaf() && !strings.HasSuffix(path, "//") {
		for i, ic := range matched.entries {
			if ic.relaxedSlash && !ic.pattern.catchAll && ic.match(c) {
				return i, matched
			}
		}
	}

	if len(*c.skipStack) == stackOffset {
		return
	}

	// A skip node pushed with params left to try is always pushed with childWildcardIdx
	// and wildcardOffset at zero, so restoring every field as saved is correct in all cases.
	skipped := c.skipStack.pop()

	matched = skipped.node
	parent = skipped.parent
	*c.params = (*c.params)[:skipped.paramCnt]
	search = path[skipped.charsMatched:]
	charsMatched = skipped.charsMatched
	childParamIdx = skipped.childParamIdx
	childWildcardIdx = skipped.childWildcardIdx
	wildcardOffset = skipped.wildcardOffset
	skipStatic = true

	goto Walk
}

// matchTrailingSlash returns a trailing slash candidate on child, a static node whose
// key appends a "/" to the matched path: either a non-strict interceptor on child itself or
// an empty match on one of its optional catch-all. Returns (-1, nil) when none match.
func matchTrailingSlash(child *node, c *routeCtx, lazy bool) (int, *node) {
	if child.isLeaf() {
		for i, ic := range child.entries {
			if ic.relaxedSlash && ic.match(c) {
				return i, child
			}
		}
	}
	// Since /foo/ and /foo/*{any} are permitted with different sets of matchers,
	// we still need to search for a matching empty catch-all.
	for _, wildcardNode := range child.wildcards {
		for i, ic := range wildcardNode.entries {
			if ic.relaxedSlash && ic.pattern.optionalCatchAll && ic.match(c) {
				if !lazy {
					// record empty match
					*c.params = append(*c.params, "")
				}
				return i, wildcardNode
			}
		}
	}
	return -1, nil
}

func (n *node) addEntry(ic *entry) {
	if !ic.narrowed() {
		// Nothing narrows it, so it is the fallback and belongs last.
		n.entries = append(n.entries, ic)
		return
	}

	pos := n.findInsertPosition(ic)
	n.entries = slices.Insert(n.entries, pos, ic)
}

func (n *node) replaceEntry(idx int, ic *entry) {
	// Priority unchanged or nothing to order on, replace in place. A port is part of the
	// pattern, so an update never changes it: the two would be different entries.
	if n.entries[idx].priority == ic.priority || !ic.narrowed() {
		n.entries[idx] = ic
		return
	}

	// Priority changed with matchers, we need to reposition the entry.
	n.entries = slices.Delete(n.entries, idx, idx+1)
	pos := n.findInsertPosition(ic)
	n.entries = slices.Insert(n.entries, pos, ic)
}

// findInsertPosition orders the entries of a node from the most narrowly targeted to the
// least, so a lookup takes the first one that accepts and never has to look further.
//
// The tiers run from what the traffic is addressed to toward how it is shaped: the port,
// which is the last piece of the target that stays out of the key, then the kind, a refined
// one carrying a precondition the kind it rides on does not, then the matchers, which are
// arbitrary predicates. Within the matcher tier, priority decides.
func (n *node) findInsertPosition(ic *entry) int {
	hasPort := ic.pattern.port != ""
	refined := ic.kind.refines()
	hasMatchers := len(ic.matchers) > 0

	for i, existing := range n.entries {
		existingHasPort := existing.pattern.port != ""
		existingRefined := existing.kind.refines()
		existingHasMatchers := len(existing.matchers) > 0

		// Entries naming a port before those accepting every one.
		if hasPort && !existingHasPort {
			return i
		}
		if hasPort != existingHasPort {
			continue
		}

		// A refined kind before the kind it rides on.
		if refined && !existingRefined {
			return i
		}

		if refined == existingRefined {
			// Entries with matchers before those without.
			if hasMatchers && !existingHasMatchers {
				return i
			}

			// Within same matchers tier, higher priority first.
			if hasMatchers && existingHasMatchers && ic.priority > existing.priority {
				return i
			}
		}
	}

	return len(n.entries)
}

func (n *node) delIC(idx int) {
	if idx >= 0 {
		copy(n.entries[idx:], n.entries[idx+1:])
		last := len(n.entries) - 1
		n.entries[last] = nil
		n.entries = n.entries[:last:last]
	}
}

// addStaticEdge inserts a static child node while maintaining sorted order by label byte.
// Uses binary search to find the insertion point.
func (n *node) addStaticEdge(child *node) {
	num := len(n.statics)
	idx := sort.Search(num, func(i int) bool {
		return n.statics[i].label >= child.label
	})
	n.statics = append(n.statics, child)
	if idx != num {
		copy(n.statics[idx+1:], n.statics[idx:num])
		n.statics[idx] = child
	}
}

// addParamEdge appends a param child node, maintaining evaluation order:
// regex params first (in insertion order), then the non-regex param ("?") last.
// This ordering ensures regex-constrained params are evaluated before the catch-all "?" param.
// Only one non-regex param is allowed per node; multiple regex params are permitted.
func (n *node) addParamEdge(child *node) {
	n.params = append(n.params, child)

	if child.key == "?" {
		return
	}

	idx := slices.IndexFunc(n.params, func(node *node) bool {
		return node.key == "?"
	})
	if idx >= 0 && idx < len(n.params)-1 {
		lastIdx := len(n.params) - 1
		n.params[idx], n.params[lastIdx] = n.params[lastIdx], n.params[idx]
	}
}

// addWildcardEdge appends a wildcard child node, maintaining evaluation order:
// regex wildcards first (in insertion order), then the non-regex wildcard ("*") last.
// This ordering ensures regex-constrained wildcards are evaluated before the catch-all "*" wildcard.
// Only one non-regex wildcard is allowed per node; multiple regex wildcards are permitted.
func (n *node) addWildcardEdge(child *node) {
	n.wildcards = append(n.wildcards, child)

	if child.key == "*" {
		return
	}

	idx := slices.IndexFunc(n.wildcards, func(node *node) bool {
		return node.key == "*"
	})
	if idx >= 0 && idx < len(n.wildcards)-1 {
		lastIdx := len(n.wildcards) - 1
		n.wildcards[idx], n.wildcards[lastIdx] = n.wildcards[lastIdx], n.wildcards[idx]
	}
}

// replaceStaticEdge updates an existing static child node in place.
// Uses binary search to locate the child by label, then replaces it.
func (n *node) replaceStaticEdge(child *node) {
	num := len(n.statics)
	idx := sort.Search(num, func(i int) bool {
		return n.statics[i].label >= child.label
	})
	if idx < num && n.statics[idx].label == child.label {
		n.statics[idx] = child
		return
	}
	panic("internal error: replacing missing edge")
}

// getStaticEdge retrieves a static child node by its label byte using binary search.
// Returns the child's index and pointer if found, or (-1, nil) if not found.
func (n *node) getStaticEdge(label byte) (int, *node) {
	num := len(n.statics)
	idx := sort.Search(num, func(i int) bool { return n.statics[i].label >= label })
	if idx < num && n.statics[idx].label == label {
		return idx, n.statics[idx]
	}
	return -1, nil
}

// getParamEdge retrieves a param child node by its key (either "?" or a regex pattern).
// Returns the child's index and pointer if found, or (-1, nil) if not found.
// Uses linear search since params are ordered by priority, not key.
func (n *node) getParamEdge(key string) (int, *node) {
	for idx, child := range n.params {
		if child.key == key {
			return idx, child
		}
	}
	return -1, nil
}

// getWildcardEdge retrieves a wildcard child node by its key (either "*" or a regex pattern).
// Returns the child's index and pointer if found, or (-1, nil) if not found.
// Uses linear search since wildcards are ordered by priority, not key.
func (n *node) getWildcardEdge(key string) (int, *node) {
	for idx, child := range n.wildcards {
		if child.key == key {
			return idx, child
		}
	}
	return -1, nil
}

// delStaticEdge removes a static child node by its label byte.
// Uses binary search to locate the child, then shifts remaining elements left.
// Sets the last element to nil before reslicing to allow garbage collection.
// No-op if no child with the given label exists.
func (n *node) delStaticEdge(label byte) {
	num := len(n.statics)
	idx := sort.Search(num, func(i int) bool {
		return n.statics[i].label >= label
	})
	if idx < num && n.statics[idx].label == label {
		copy(n.statics[idx:], n.statics[idx+1:])
		n.statics[len(n.statics)-1] = nil
		n.statics = n.statics[:len(n.statics)-1]
	}
}

// delParamEdge removes a param child node by its key (either "?" or a regex pattern).
// Shifts remaining elements left after removal and clears the last slot for GC.
// No-op if no param with the given key exists.
func (n *node) delParamEdge(key string) {
	idx := slices.IndexFunc(n.params, func(p *node) bool { return p.key == key })
	if idx >= 0 {
		copy(n.params[idx:], n.params[idx+1:])
		n.params[len(n.params)-1] = nil
		n.params = n.params[:len(n.params)-1]
	}
}

// delWildcardEdge removes a wildcard child node by its key (either "*" or a regex pattern).
// Shifts remaining elements left after removal and clears the last slot for GC.
// No-op if no wildcard with the given key exists.
func (n *node) delWildcardEdge(key string) {
	idx := slices.IndexFunc(n.wildcards, func(p *node) bool { return p.key == key })
	if idx >= 0 {
		copy(n.wildcards[idx:], n.wildcards[idx+1:])
		n.wildcards[len(n.wildcards)-1] = nil
		n.wildcards = n.wildcards[:len(n.wildcards)-1]
	}
}

func (n *node) searchPattern(key string) (matched *node) {
	current := n
	search := key

	for len(search) > 0 {
		switch search[0] {
		case bracketDelim:
			end, paramName := parseBraceSegment(search)
			if paramName == "" {
				goto STATIC
			}
			_, child := current.getParamEdge(paramName)
			if child == nil {
				return nil
			}
			current = child
			search = search[end+1:]
			continue
		case starDelim, plusDelim:
			end, paramName := parseBraceSegment(search)
			if paramName == "" {
				goto STATIC
			}
			_, child := current.getWildcardEdge(paramName)
			if child == nil {
				return nil
			}
			current = child
			search = search[end+1:]
			continue
		}

	STATIC:
		label := search[0]
		_, child := current.getStaticEdge(label)
		if child == nil {
			return nil
		}

		keyLen := min(len(child.key), len(search))
		if search[:keyLen] != child.key[:keyLen] {
			return nil
		}
		search = search[keyLen:]
		current = child
	}

	return current
}

func (n *node) searchName(key string) (matched *node) {
	current := n
	search := key

	for len(search) > 0 {
		label := search[0]
		_, child := current.getStaticEdge(label)
		if child == nil {
			return nil
		}

		keyLen := min(len(child.key), len(search))
		if search[:keyLen] != child.key[:keyLen] {
			return nil
		}
		search = search[keyLen:]
		current = child
	}

	return current
}

// parseBraceSegment extracts the node key from a param or wildcard segment in an interceptor pattern.
// It returns the index of the closing brace and the corresponding node key used for tree lookups:
//   - For params {name}: returns (end, "?")
//   - For wildcards *{name} or +{name}: returns (end, "*")
//   - For params with regex {name:pattern}: returns (end, "pattern")
//   - For wildcards with regex *{name:pattern}: returns (end, "pattern")
//   - For literal '*' or '+' (not followed by '{') and invalid/malformed segments:
//     returns (0, "") to signal static handling
//
// This is a lightweight parser that does not fully validate the segment. It assumes the caller
// will verify that the retrieved interceptor's pattern matches the search pattern after tree lookup.
func parseBraceSegment(pattern string) (int, string) {
	length := len(pattern)
	if length == 0 {
		return 0, pattern
	}

	key := "?"
	if pattern[0] == starDelim || pattern[0] == plusDelim {
		if length < 2 || pattern[1] != bracketDelim {
			// Literal '*' or '+': the wildcard syntax requires an immediate '{'.
			return 0, ""
		}
		key = "*"
	}

	end := braceIndex(pattern, 0)
	if end <= 0 {
		return 0, ""
	}

	idx := strings.IndexByte(pattern[:end], ':')
	if idx == -1 {
		return end, key
	}
	// Handle missing param name such as {:[A-z]} here since it would be an invalid pattern anyway.
	if idx == 0 {
		return 0, ""
	}

	return end, pattern[idx+1 : end]
}

func (n *node) isLeaf() bool {
	return len(n.entries) > 0
}

// findAdmission returns the index of the entry on n that admits the traffic of kind admit on
// the port of c. An admission entry selects on the port and the kind alone: it carries no
// matcher, because nothing has been read off the connection yet to evaluate one against.
//
// It is also the only kind of entry that can sit on a hostname node, since a per-message
// entry's tokens always end in its path and it is never a leaf before the '/'. The path test
// is what keeps that structural fact checked rather than assumed.
func findAdmission(n *node, c *routeCtx, admit Kind) (int, bool) {
	for i, e := range n.entries {
		if e.pattern.path == "" && e.kind == admit && e.acceptsPort(c) {
			return i, true
		}
	}
	return -1, false
}

func (n *node) String() string {
	return n.string(0)
}

func (n *node) string(space int) string {
	sb := strings.Builder{}
	sb.WriteString(strings.Repeat(" ", space))
	if n.key == "" {
		sb.WriteString("root:")
	} else {
		sb.WriteString("path: ")
		sb.WriteString(n.key)
	}
	if n.host {
		sb.WriteString(" (host)")
	}

	if len(n.params) > 0 {
		sb.WriteString(" [params: ")
		sb.WriteString(strconv.Itoa(len(n.params)))
		sb.WriteByte(']')
	}

	if len(n.wildcards) > 0 {
		sb.WriteString(" [wildcards: ")
		sb.WriteString(strconv.Itoa(len(n.wildcards)))
		sb.WriteByte(']')
	}

	for _, ic := range n.entries {
		sb.WriteByte('\n')
		sb.WriteString(strings.Repeat(" ", space+8))
		sb.WriteString("=> ")
		sb.WriteString(ic.pattern.str)

		sb.WriteString(" [kind: ")
		sb.WriteString(ic.kind.String())
		sb.WriteByte(']')

		if len(ic.matchers) > 0 {
			sb.WriteString(" [matchers: ")
			for i, matcher := range ic.matchers {
				if i > 0 {
					sb.WriteString(", ")
				}
				if m, ok := matcher.(fmt.Stringer); ok {
					sb.WriteString(m.String())
				} else {
					sb.WriteString(reflect.TypeOf(matcher).String())
				}
			}
			sb.WriteByte(']')
		}
		sb.WriteString(" [priority: ")
		sb.WriteString(strconv.FormatUint(uint64(ic.priority), 10))
		sb.WriteByte(']')
	}

	sb.WriteByte('\n')

	for _, child := range n.statics {
		sb.WriteString("  ")
		sb.WriteString(child.string(space + 4))
	}
	for _, child := range n.params {
		sb.WriteString("  ")
		sb.WriteString(child.string(space + 4))
	}
	for _, child := range n.wildcards {
		sb.WriteString("  ")
		sb.WriteString(child.string(space + 4))
	}

	return sb.String()
}

type skipStack []skipNode

func (n *skipStack) pop() skipNode {
	skipped := (*n)[len(*n)-1]
	*n = (*n)[:len(*n)-1]
	return skipped
}

type skipNode struct {
	node             *node
	parent           *node
	charsMatched     int
	paramCnt         int
	childParamIdx    int
	childWildcardIdx int
	wildcardOffset   int
}
