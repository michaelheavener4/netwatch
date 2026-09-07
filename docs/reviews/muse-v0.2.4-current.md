# Muse Hostile Review — netwatch

## Repository state

* branch: `main`
* HEAD commit: `4c895bb27a9773a7233b089e8252da2425e8aeba`
* version: `0.2.5` (`VERSION` in `netwatch.py:27`)
* test count observed: 88 passing (`python3 -m unittest discover -s tests`, OK)
* review date: 2026-09-07 (UTC)
* reviewer role: hostile security/correctness reviewer; no source changes made

Prior handoff described HEAD as `c777495` / v0.2.4. The actual current HEAD at review time is `4c895bb` (v0.2.5, "Fix F2: distinguish peered UDP endpoints from service candidates"). This review evaluates the actual current tree, including the F2 fix.

## Final verdict

**FAIL**

One material correctness/evidence problem remains (specific-address listener silence). No other HIGH finding survived scrutiny.

## Findings

### Finding 1 — Specific non-loopback listener gets zero heuristic note while wildcard is warned (false negative)

## Severity

HIGH

## Exact location

`netwatch.py: find_unusual()` (lines ~535–581). Emitting branches only for:

* `exposure == "wildcard" and privileged`
* `exposure == "wildcard"`
* `privileged and exposure == "loopback"`
* bare `privileged`

Interacts with `netwatch.py: _ip_kind()` (~352–370), which correctly returns `private` / `link-local` / `public` for these addresses, but no branch consumes those values unless `conn.local_port < 1024`.

`netwatch.py: is_service()` correctly returns True for the TCP LISTEN rows in question — the silence is in `find_unusual()`, not classification.

## Evidence actually available

A `Connection` with `state == "LISTEN"`, `proto` tcp/tcp6, and a concrete non-loopback, non-wildcard bind, e.g.:

* `local_ip="192.168.1.10"`, `local_port=8000`
* `local_ip="10.0.0.5"`, `local_port=8000`
* `local_ip="172.17.0.1"` (Docker/bridge), `local_port=8000`
* `local_ip="fe80::1"` (link-local IPv6), `local_port=8000`

Verified live-logic on current tree: `find_unusual([OwnedConnection(conn, [SocketOwner(100, "app")])]) == []` for all four binds (high port, attributed). `_ip_kind()` knows they are `private`/`link-local`, but that evidence is discarded.

## Current inference

Zero notes for those sockets. In the same report, `LISTEN 0.0.0.0:8000` yields:

```text
listening on all interfaces: tcp 0.0.0.0:8000 (...) - reachable from the network, not just localhost.
```

The footer when nothing fires is:

```text
Nothing stood out. (Absence of flags is not proof of safety.)
```

## Why it fails

The asymmetric treatment is not justified by the evidence. Netwatch proves the bind address; it proves nothing about routing, firewall policy, interface state, or VPN/bridge topology — in either direction. A non-loopback specific bind (LAN address, bridge address, link-local) is a genuine LAN/bridge/VPN-reachable candidate: the exact shape of a dev server bound to `192.168.1.10`, a Docker bridge listener on `172.17.0.1`, or link-local IPv6 exposure. Warning wildcard as "reachable from the network" while staying silent on these teaches the operator `no flag = less exposed / safe`, with no evidentiary basis for the distinction. The footer disclaimer does not undo the learned contrast because the rest of the report affirmatively flags one pattern and not the other.

This review does NOT claim proven end-to-end reachability for these binds (firewall/routing unknown). The defect is the omission of a meaningful, evidence-backed candidate pattern alongside a warned pattern, creating a false-negative direction error.

## Concrete example

Fake-`/proc` TCP line for a LAN bind (high port, attributed):

```text
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0A01A8C0:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 9001
```

(`0A01A8C0` decodes to `192.168.1.10`, `1F40` = 8000.) With `socket:[9001]` held by PID 100 in the fake tree, current `summary` shows the listener in "Listening ports" but `find_unusual()` returns `[]` for it. The identical service on `0.0.0.0:8000` (`00000000:1F40`) produces an `all interfaces` note. Live equivalents: `python3 -m http.server --bind 192.168.1.10 8000`, Docker `-p 172.17.0.1:8000:80`.

## Analyst impact

Analyst dismisses a LAN/bridge-reachable service because "netwatch didn't flag it," while the same service on wildcard would have been flagged. Missed persistence / missed lateral-movement surface. False negatives are more dangerous than the noise fixed in F2.

## Smallest correction

Emit one neutral, non-reachability-proving note per non-loopback, non-wildcard listener, e.g.:

```text
listening on specific address 192.168.1.10:8000 — reachable from hosts that can route to that address; firewall/routing/interface state not checked; confirm you expect this binding.
```

Constraints for the fix: must not claim proven reachability; must keep one-note-per-socket (L1); must keep loopback quiet when non-privileged (existing locked behavior); must apply symmetrically to TCP listeners and peerless-UDP listener candidates.

## Regression test

`find_unusual` on attributed `LISTEN 192.168.1.10:8000` (and `172.17.0.1:8000`, high port) — must FAIL on current tree (returns `[]`) and PASS after fix (exactly one note naming the bound address, containing neither `all interfaces` nor any firewall/reachability verdict). Companion negative controls that must stay passing: loopback high-port listener stays quiet; wildcard behavior unchanged.

---

### Finding 2 — Loopback ESTABLISHED counted under "Established remote connections" (shorthand overclaim)

## Severity

LOW (kept LOW deliberately; mitigated by adjacent column)

## Exact location

`netwatch.py: build_summary()` (~607: `established = [r for r in records if state == "ESTABLISHED"]`, no loopback exclusion) and `netwatch.py: render_summary()` (~662: section header `"Established remote connections (N):"` with `REMOTE-KIND` column from `_ip_kind(conn.remote_ip)`).

## Evidence actually available

Kernel `ESTABLISHED` state plus endpoints, e.g. `127.0.0.1:5000 -> 127.0.0.1:8080` (local IPC over TCP: `ssh -L`, `kubectl port-forward`, browser↔proxy chatter).

## Current inference

Section header asserts "remote connections." Verified: such a loopback pair is included in `summary.established` (count 1) and rendered under that header.

## Why it fails

Loopback IPC is not remote. The header overstates what the state+endpoints establish. Mitigation: the same row's `REMOTE-KIND` cell correctly says `loopback`, so an attentive reader can resolve the contradiction — hence LOW, not MEDIUM/HIGH.

## Concrete example

`ESTABLISHED 127.0.0.1:5000 -> 127.0.0.1:8080`, attributed. Current `summary` lists it under "Established remote connections" with `REMOTE-KIND loopback`.

## Analyst impact

At most a brief misdirect ("hunt a remote C2 that is local port-forward chatter") before the `REMOTE-KIND` column corrects it. No missed exposure; no wrong attribution.

## Smallest correction

Rename to `"Established sockets"` (let `REMOTE-KIND` do the work) or split loopback vs non-loopback counts. One-line header change plus test.

## Regression test

Attributed loopback `ESTABLISHED` pair must FAIL on current tree (appears under header containing "remote") and PASS after fix (header neutral or loopback split; `REMOTE-KIND loopback` preserved).

## What survived previous fixes

* **F2 UDP semantics (v0.2.5): VERIFIED FIXED.** `is_service()` now requires peerlessness for UDP (`is_listening or is_peerless_udp`); `_remote_is_zero` gates on unspecified remote + port 0; `build_summary` splits `udp_services` (peerless listener candidates) vs `udp_peered` (concrete remote, direction unknown); `render_summary` and `EXPLAIN_TEXT` use matching terminology; peered rows verified to yield zero heuristic notes (tested: `0.0.0.0:45056 -> 8.8.8.8:53` → `is_service False`, `find_unusual []`). Peerless wildcard still flagged as listener candidate. IPv4/IPv6 share the same `_remote_is_zero` path.
* **F1 privileged-port (v0.2.4): REMAINS FIXED.** No `only a privileged process ... can bind here` string in current source; all three `<1024` branches use range-label + `check that you expect this service`. `<1024` terminology retained as conventional classification per handoff — not re-reported.
* **L2 attribution wording:** `? (unattributed)` / `process attribution unavailable` / `Unreadability does not identify a socket owner` all present; no another-user/root-necessity causal claim found.
* **L1 one-note-per-socket + loopback distinction, L8 ragged-row formatter, control-char sanitization, malformed-line warnings, SIGPIPE 141, IPv4 decode, `TIME_WAIT`/inode-0 non-attribution:** all confirmed present and covered by tests (88/88 passing).

## Investigated and rejected

* **F1 attribution race (PID/inode false attribution): REJECTED (reaffirmed).** Re-audited `build_inode_map()` → `attribute_owners()`. Dominant failure remains *missed* attribution (exit/close between table scan and fd scan → `unattributed`, safe direction). Systemic *false* attribution needs same-inode reuse across distinct sockets; sockfs inode allocation is monotonic (`get_next_ino`), not prompt-reuse, so prompt collision needs counter wrap — practically constrained. PID reuse alone does not plant `socket:[N]` in the new process without fd inheritance/passing (contrived). Multi-holder output lists all holders rather than electing one. Non-atomic `/proc` cannot yield atomic snapshots read-only; demanding race-freedom would violate project constraints. Not reported.
* **Process-name identity (comm/cmdline spoof, 32-char truncation): REJECTED as material bug.** `comm` is capped at 16 chars (`TASK_COMM_LEN`) so truncation only affects the `cmdline`-basename fallback; spoofability is real but README security considerations already state names are claims not authentication (same caveat as `ps`), and PID numbers (the actionable part) are kernel-provided. At most a future LOW; not reported as a finding.
* **Unreadable `/proc/<pid>/fd` count: REJECTED.** Count is cause-neutral in output with explicit `does not identify a socket owner` disclaimer; docstring enumerates kthreads/races. Adjacency risk noted but contained — informational at most.
* **`unknown owner` vs `unattributed` terminology: REJECTED.** Same-sentence pairing with `process attribution unavailable` keeps the existential reading contained; locked by `TestL2AttributionLanguage`. Not a material misunderstanding.
* **IPv4-mapped IPv6 (`::ffff:0.0.0.0` local): REJECTED.** `_ip_kind` would miss the wildcard branch for an explicitly mapped local bind, but real wildcard binds decode to `::` (verified path), and no live-shape local mapped-wildcard row was established. Theoretical/rare — not reported.
* **Parser field-shift / malformed robustness: REJECTED.** Shape anchors (`_SLOT_RE`/`_QUEUE_RE`/`_HEX_RE`), `<10`-field rejection, and malformed-count warnings verified; numeric-insertion residual is documented and kernel-hypothetical. No concrete bypass found.
* **TCP pre/post-handshake wording (`connected/transient`): REJECTED.** `transient` explicitly hedges `SYN_*`/`CLOSE_WAIT`/`FIN_WAIT`/`TIME_WAIT`; `TIME_WAIT` correctly excluded from `established`. Ordinary shorthand, not material.
* **F2 regression sweep (items 1–6): PASSED.** Peered UDP not a service; no reachability wording for peered; peerless still candidate; summary sections match; v4/v6 share `_remote_is_zero`; TCP paths unchanged (all 81 pre-existing tests plus 7 new F2 tests pass).

## Recommended next fix

Fix Finding 1 only: add the neutral specific-bind listener note described above (no reachability verdict, one note per socket, loopback-quiet preserved). It is the single remaining HIGH, deterministic, and testable within stdlib/read-only/fake-proc constraints.

## Residual limitations

* Point-in-time snapshot: short-lived sockets/PIDs churn between runs and between the table scan and fd scan; missed attribution is expected and reported as `unattributed`.
* No firewall/routing/interface/VPN visibility: no heuristic, current or proposed, proves end-to-end reachability. All exposure notes are bind-address candidates plus a prompt to check expectation.
* Local visibility only: other netns/containers, other machines, and `/proc`-hiding rootkits are out of scope.
* No verdicts: `summary` heuristics are prompts; absence of flags is not proof of safety (footer retained).
* Positional `/proc/net` parsing has one documented undetectable edge (purely numeric pre-`uid` insertion); everything detectable is rejected and warned.
