# F3 — Specific-address listener exposure semantics

## Mission

Implement **only Muse Finding 2 (F3)** in the current `netwatch` repository.

Current expected starting state:
- branch: `main`
- F2 UDP semantics has already shipped
- previous fixes L1, L2, L8, and F1 are already shipped

Before doing anything, inspect the current repository rather than assuming exact line numbers or helper names.

---

## Problem

`find_unusual()` currently warns for wildcard listeners such as:

```text
0.0.0.0:8000
```

but can emit no warning for a listener bound to a specific non-loopback address such as:

```text
192.168.1.10:8000
172.17.0.1:8000
fe80::1234:8000
```

The current heuristic therefore distinguishes wildcard from loopback, but silently omits the meaningful middle category: a listener bound to a specific non-loopback address.

This is a **false-negative-by-omission** problem.

The fix must NOT claim that a specific address is definitely reachable from the network. `netwatch` does not inspect routing, firewall rules, interface state, VPN topology, or bridge topology.

The evidence available is the socket's bind address and listener state.

---

# Evidence invariant

For a TCP listening socket, `/proc/net/tcp*` establishes that a socket exists in `LISTEN` state at the reported local address/port.

From the local bind address, netwatch may distinguish:

1. **Loopback** — intentionally local-only bind candidate.
2. **Wildcard** — bound to all local addresses represented by the wildcard endpoint.
3. **Specific non-loopback** — bound to one particular non-loopback address.

For category 3, netwatch may say that the socket **may be reachable from hosts that can route to that address**, but it must explicitly avoid claiming actual end-to-end reachability.

Do not infer:
- firewall state
- routing
- interface state
- global/LAN/VPN exposure
- attacker reachability
- application intent

from the bind address alone.

---

# Scope

This task is ONLY about F3.

Do NOT fix:
- UDP issues beyond the already-shipped F2 behavior
- PID/inode attribution races
- process identity/name issues
- TCP terminology unrelated to F3
- IPv4-mapped IPv6 issues unless strictly required to implement F3 consistently
- parser issues
- unreadable `/proc` wording
- unrelated refactors

If you discover another issue, document it in the final report but do not fix it.

---

# Test-first requirement

Before changing production code:

1. Inspect existing tests and the current `find_unusual()` behavior.
2. Add focused F3 regression tests.
3. Run those tests against the unmodified production implementation.
4. Demonstrate that the new tests fail for the intended reason.
5. Only then modify production code.

Do NOT weaken or rewrite existing tests merely to make them pass.

If an existing assertion genuinely encodes behavior that F3 requires changing, explicitly identify it before changing it and preserve all unrelated coverage.

---

# Required regression tests

Add focused tests covering at least:

## Test 1 — IPv4 specific private/LAN bind

A listening TCP socket such as:

```text
192.168.1.10:8000
```

with a normal non-privileged port and an attributed process.

Expected:
- exactly one F3 exposure note
- no wildcard / "all interfaces" wording
- no assertion of proven network reachability
- wording identifies the specific bind address

## Test 2 — IPv4 bridge/private bind

Example:

```text
172.17.0.1:8000
```

Expected to receive the same category of neutral specific-bind note.

## Test 3 — IPv6 link-local/specific non-loopback bind

Use an appropriate specific IPv6 address represented by the existing `Connection`/parser model.

Expected to be treated as specific non-loopback rather than loopback or wildcard.

## Test 4 — loopback remains distinct

For example:

```text
127.0.0.1:8000
```

Expected:
- no F3 specific-address exposure note merely because it is non-wildcard
- existing loopback behavior preserved

## Test 5 — wildcard remains distinct

For example:

```text
0.0.0.0:8000
```

Expected:
- existing wildcard heuristic remains unchanged
- it must not be converted into the F3 specific-address wording

## Test 6 — privileged specific bind preserves one-note behavior

A specific non-loopback listener on `<1024` should not generate multiple independent exposure notes merely because it satisfies both "specific address" and "privileged port" categories.

Preserve the L1 invariant: one coherent heuristic note per service socket where the existing implementation provides one.

Use the current code's actual intended behavior to determine the precise expected wording/count.

---

# UDP interaction

F2 has already established that:

- peerless UDP endpoints are listener candidates
- peered UDP endpoints are not treated as services

If F3's generic service classification applies to peerless UDP, ensure the new specific-address logic does not accidentally make peered UDP endpoints into exposure findings.

Do not redesign F2.

---

# Wording requirements

The new specific-bind wording must be evidence-based.

Acceptable semantic shape:

> listening on specific address: tcp 192.168.1.10:8000 (...) — may be reachable from hosts that can route to this address; firewall/routing/interface state not checked; confirm you expect this binding.

The exact prose may be improved for clarity, but it must preserve these properties:

- says it is a specific-address bind
- does not call it wildcard
- does not claim actual reachability
- acknowledges routing/firewall/interface uncertainty
- encourages verification of expected binding

Avoid vague wording such as simply:

> reachable from the network

because that would repeat the evidence-overclaim problem we just fixed elsewhere.

Do not state that private addresses are inherently safe or inherently globally reachable.

---

# Classification

Inspect the existing `_ip_kind()` and related helpers.

Prefer reusing existing address classification rather than duplicating IP logic.

The intended semantic distinction is approximately:

```text
loopback       → local-only category
wildcard       → wildcard category
specific-other → F3 specific-bind category
```

Do not accidentally classify every non-loopback address as globally exposed.

Do not assume `_ip_kind()`'s existing labels necessarily map directly to the final heuristic; inspect the actual code.

---

# One-note invariant

Preserve the existing `find_unusual()` structure and L1 behavior.

If a socket satisfies multiple properties, do not blindly add multiple independent notes.

The implementation should produce one coherent note that communicates the relevant evidence without duplication.

---

# Documentation

Update README/documentation only as necessary to explain the new specific-address listener heuristic and its limitations.

Do not perform unrelated documentation cleanup.

---

# Verification

After implementation run:

```bash
python3 -m unittest discover -s tests
```

Record the exact final test count and result.

Then run all four live commands:

```bash
python3 netwatch.py summary
python3 netwatch.py connections
python3 netwatch.py processes
python3 netwatch.py explain
```

Record the exit status of each.

Inspect:

```bash
git diff
git status --short
```

Confirm there are no unrelated changes.

Pay special attention to live summary output:
- existing wildcard warnings should still make sense
- peerless UDP behavior from F2 should remain intact
- no peered UDP endpoint should become an F3 service warning

---

# Commit/push

Only after:
- regression tests failed before the fix
- the implementation fixes F3
- full test suite passes
- all four live CLI commands exit successfully
- diff contains only intended F3 changes
- no unrelated behavior was changed

then commit and push to `origin/main`.

Suggested commit message:

```text
Fix F3: flag specific non-loopback listeners
```

Increment the project version appropriately from the current version.

---

# Final handoff

Do not paste a huge report into chat.

Report concisely:

- starting HEAD
- final HEAD
- tests added
- proof they failed before the fix
- final full-suite result
- four live command exit statuses
- files changed
- version
- commit hash/message
- push status
- exact F3 evidence invariant implemented
- residual limitations
- any unrelated findings discovered but intentionally NOT fixed

The repository state and commit are the authoritative implementation artifact.

## Final rule

**F3 ONLY.**

The objective is the smallest test-backed correction that stops netwatch from silently omitting specific non-loopback listener binds while avoiding any unsupported claim of actual network reachability.