# netwatch

A small defensive Linux network-observation tool. It shows you what network
activity is occurring **on your own machine** — listening ports, active
connections, and the processes behind them — using only the Linux
`/proc` filesystem. Standard library only, no root, no network access,
no scanning of other machines.

## Installation

Requires Python 3.12+ on Linux. No dependencies to install.

```bash
git clone <this-repo>   # or copy the netwatch/ directory
cd netwatch
./netwatch.py --help
```

Optional: put it on your `PATH`.

```bash
ln -s "$PWD/netwatch.py" ~/.local/bin/netwatch
netwatch summary
```

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

## Usage

```bash
netwatch connections   # all observed TCP/UDP sockets, listening vs connected
netwatch processes     # which processes own those sockets (best effort)
netwatch summary       # security-oriented overview + things worth a look
netwatch explain       # teach the concepts (TCP states, /proc, inodes, ...)
```

`netwatch` with no subcommand prints help. Exit code is `0` on success,
`1` if the socket tables cannot be read at all (e.g. not on Linux).
Unreadable processes or missing table files produce warnings on stderr,
never a crash.

Example (abridged):

```
$ netwatch summary
Observed 29 socket(s).

Counts by protocol:
  tcp: 12
  ...
Listening ports (7):
PROTO  LOCAL           UID  INODE
tcp    0.0.0.0:22      0    10807
...

Anything unusual (local heuristics only - prompts, not verdicts):
  - listening on all interfaces: tcp 0.0.0.0:22 ...
```

## Architecture

One file, deliberately: `netwatch.py` (~600 lines). The pipeline is linear
and each stage is independently testable:

```
read /proc/net/{tcp,tcp6,udp,udp6}   ->  parse lines into Connection records
scan /proc/<pid>/fd                  ->  build inode -> [SocketOwner] map
join on inode number                 ->  OwnedConnection records
classify + render                    ->  connections | processes | summary
```

Key functions:

| Function | Job |
|---|---|
| `decode_hex_ip` / `decode_hex_port` | Decode the kernel's hex address format |
| `parse_proc_net_line` | One `/proc/net/*` line → `Connection` (or `None`) |
| `get_connections` | Read all four socket tables; warn-and-skip on failure |
| `build_inode_map` | Scan every process's fd symlinks for `socket:[inode]` |
| `attribute_owners` | Join connections to owners on the inode number |
| `build_summary` / `find_unusual` | Pure functions: counts, groups, local-only heuristics |
| `render_*` / `format_table` | Plain-text tables, no dependencies |

All filesystem access takes a `proc_root` parameter (default `/proc`), which
is exposed as `--proc-root`. That single decision makes the whole tool
testable against a fake `/proc` tree built in a temp directory — see
`tests/test_netwatch.py`.

## Why it works (the Linux behind it)

**`/proc` is the kernel thinking out loud.** It is not a real filesystem on
disk; it is a window into kernel data structures, rendered as text files.
`/proc/net/tcp` is the kernel's TCP socket table printed as rows. Reading it
changes nothing, needs no privileges, and generates zero network traffic —
that is why netwatch can be purely read-only.

**The hex addresses look backwards because they are.** The kernel prints each
32-bit word of an IP address in *host* byte order, which on x86/64 and ARM is
little-endian. So `0100007F` is the bytes `01 00 00 7F` stored least-significant
first; reversing gives `7F 00 00 01` = `127.0.0.1`. Ports are printed
big-endian (normal order), so `0035` hex is just 53. IPv6 rows hold 32 hex
digits with the same per-4-byte reversal. `decode_hex_ip()` exists only to
undo this historical quirk, and uses the stdlib `ipaddress` module so output
is normalized (`::` instead of 32 zeros).

**The inode is the rendezvous key.** A socket is a kernel object identified by
an inode number, shown in the `inode` column of the socket tables. Separately,
every process's open files appear as symlinks under `/proc/<pid>/fd/`, and a
socket fd looks like `socket:[12345]` — the same number. Matching the two
lists is a *join on inode number*. That is the entire attribution mechanism;
tools like `ss -p` do fundamentally the same thing.

**Unprivileged users see only their own file descriptors.** Linux discretionary
access control denies you reads of `/proc/<pid>/fd/` belonging to other users
(typically root-owned daemons like sshd or a system DNS resolver). Those reads
fail with `PermissionError`, which netwatch counts and reports instead of
crashing — hence "unattributed" sockets. Related reasons attribution can fail:
the process exited between the two scans (a race), kernel threads own no fds,
containers have separate network namespaces (a host-wide read may not see or
may misattribute their sockets), and `hidepid=2` mounts hide other users'
processes entirely. Run `netwatch explain` for the full story.

**UDP rows have no state.** TCP tracks connection lifecycle (LISTEN →
handshake → ESTABLISHED → goodbye handshake → TIME_WAIT), and the kernel
reports it. UDP is connectionless — a row is just a local port that sent or
received datagrams — so the kernel's state column is meaningless there and
netwatch displays `STATELESS`. Similarly, `TIME_WAIT` rows report inode `0`
because the socket itself is already gone; only the kernel's bookkeeping
record remains, so they can never be attributed.

## Limitations

- **Linux only.** Requires a `/proc` filesystem with `/proc/net/*`.
- **A point-in-time snapshot.** Sockets open and close constantly; a
  short-lived connection can appear and vanish between runs. This is an
  observer, not a monitor — there is no continuous capture or alerting.
- **Local visibility only.** It cannot see other machines, container network
  namespaces from the outside, or traffic that does not involve a local
  socket. It is not a packet sniffer (see `tcpdump`/`wireshark` for that,
  which do need privileges).
- **No verdicts.** `summary` flags wildcard listeners, privileged ports, and
  unattributed connections as *prompts to investigate*, never as threats. A
  clean report is not proof of safety — a rootkit that hides from `/proc`
  would also hide from this tool.
- **Attribution gaps without root.** Expect root-owned service sockets
  (port 22, 53, 631, DHCP, …) to show as unattributed when run as a normal
  user. That is the permission model working, not a bug.

## Security considerations

- **Attack surface: reads only.** The tool opens files under `/proc` for
  reading and prints text. It never writes configuration, never opens a
  socket, never executes another program, never sends data anywhere. The
  worst it can do is print something surprising.
- **Input is untrusted-shaped but local.** Process names come from
  `/proc/<pid>/comm` (or `cmdline` as fallback) and are printed as-is; a
  hostile local process could embed terminal escape sequences or misleading
  names in them. netwatch does not sanitize these — do not pipe its output
  into a shell, and treat process names as claims, not proof. (Same caveat
  applies to `ps`.)
- **No privilege escalation path.** It does not need setuid, sudo, or
  capabilities, and must never be given them — extra privilege would only
  widen what a bug could touch, for no functional gain.
- **Privacy of output.** Connection lists reveal browsing endpoints, local
  network layout (VPN/Tailscale addresses), and running services. Fine to
  study locally; think before pasting full output into a public forum.
- **Denial-of-service resistance.** All parsing is bounded line-by-line
  string work; malformed `/proc` lines are skipped, per-PID and per-fd
  errors are caught individually so one vanishing process cannot abort a
  scan. There is no recursion and no unbounded allocation keyed on input.

## Second-iteration ideas

- Continuous mode (`--watch N`) re-rendering the summary every N seconds.
- Diff mode: highlight sockets that appeared/disappeared since the last run.
- `--json` output for scripting.
- Container awareness: note when a socket likely lives in another netns.
- Sanitizing control characters in process names before printing.
