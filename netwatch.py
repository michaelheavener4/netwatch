#!/usr/bin/env python3
"""netwatch - defensive Linux network-observation tool (standard library only).

Reads local kernel state from /proc (no network connections, no scanning,
no configuration changes, no root required) and presents it in a
beginner-friendly way.

Subcommands:
  connections   currently observed TCP/UDP sockets (listening vs. connected)
  processes     processes associated with those sockets (best effort, no root)
  summary       concise security-oriented overview + heuristics worth a look
  explain       teach the Linux concepts behind the output
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import os
import re
import signal
import sys
from dataclasses import dataclass, field


VERSION = "0.2.6"
DEFAULT_PROC_ROOT = "/proc"

# TCP state codes as they appear in /proc/net/tcp (see tcp_states.h in Linux).
TCP_STATES: dict[str, str] = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

# /proc/net/* files we read: (filename, protocol label).
PROC_NET_FILES: tuple[tuple[str, str], ...] = (
    ("tcp", "tcp"),
    ("tcp6", "tcp6"),
    ("udp", "udp"),
    ("udp6", "udp6"),
)

_SOCKET_RE = re.compile(r"^socket:\[(\d+)\]$")
# Shape anchors for positional /proc/net/* columns. The socket tables carry
# no version marker, so a kernel (or patch) inserting a column before `uid`
# would otherwise shift uid/inode silently. These anchors convert every
# *detectable* drift into a skipped line (which is then reported); a purely
# numeric insertion is byte-identical to a genuine row (e.g. a TIME_WAIT
# record) and remains undetectable in principle - see README limitations.
_SLOT_RE = re.compile(r"^\d+:$")                    # "0:"
_QUEUE_RE = re.compile(r"^[0-9A-Fa-f]+:[0-9A-Fa-f]+$")  # "00000000:00000000"
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")             # retrnsmt counter


class NetwatchError(Exception):
    """Fatal, user-facing netwatch error."""


# Conventional Unix exit status for death by SIGPIPE (128 + 13).
_SIGPIPE_STATUS = 141


def restore_sigpipe() -> None:
    """Restore default SIGPIPE handling.

    Python sets SIGPIPE to SIG_IGN at startup, which turns a closed output
    pipe (`netwatch summary | head`) into a BrokenPipeError traceback and a
    bogus exit code. Restoring SIG_DFL makes the process die silently by
    signal like any well-behaved Unix tool.
    """
    sigpipe = getattr(signal, "SIGPIPE", None)
    if sigpipe is None:
        return
    try:
        signal.signal(sigpipe, signal.SIG_DFL)
    except (OSError, ValueError):
        pass


@dataclass
class Connection:
    proto: str        # "tcp", "tcp6", "udp", "udp6"
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str        # e.g. "LISTEN"; "STATELESS" for UDP
    uid: int
    inode: int


@dataclass
class SocketOwner:
    pid: int
    name: str


@dataclass
class OwnedConnection:
    connection: Connection
    owners: list[SocketOwner] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def decode_hex_ip(raw: str) -> str:
    """Decode a /proc-style hex IP address to a human-readable string.

    The kernel prints each 32-bit word of the address in *host* byte order,
    which on x86/ARM is little-endian, so every 4-byte group must be
    byte-reversed. 8 hex chars -> IPv4, 32 hex chars -> IPv6.
    """
    try:
        data = bytes.fromhex(raw.strip())
    except ValueError as exc:
        raise ValueError(f"not valid hex address: {raw!r}") from exc
    if len(data) == 4:
        return str(ipaddress.IPv4Address(data[::-1]))
    if len(data) == 16:
        grouped = b"".join(data[i:i + 4][::-1] for i in range(0, 16, 4))
        return str(ipaddress.IPv6Address(grouped))
    raise ValueError(f"unexpected address length ({len(data)} bytes): {raw!r}")


def decode_hex_port(raw: str) -> int:
    """Decode a /proc-style hex port (always big-endian, no reversal)."""
    port = int(raw.strip(), 16)
    if not 0 <= port <= 65535:
        raise ValueError(f"port out of range: {raw!r}")
    return port


def split_address(addr: str) -> tuple[str, int]:
    """Split a 'HEXIP:HEXPORT' field into (readable IP, port)."""
    ip_hex, _, port_hex = addr.rpartition(":")
    if not ip_hex or not port_hex:
        raise ValueError(f"malformed address field: {addr!r}")
    return decode_hex_ip(ip_hex), decode_hex_port(port_hex)


def parse_proc_net_line(line: str, proto: str) -> Connection | None:
    """Parse one data line of /proc/net/{tcp,tcp6,udp,udp6}.

    Returns None for header lines, blank lines, and malformed lines.
    Only the first 10 whitespace-separated fields are used, so extra
    columns added by newer kernels are ignored.
    """
    parts = line.split()
    if len(parts) < 10:
        return None
    if parts[0] == "sl" or not _SLOT_RE.match(parts[0]):
        return None  # header line or garbage
    if not (_QUEUE_RE.match(parts[4]) and _QUEUE_RE.match(parts[5])
            and _HEX_RE.match(parts[6])):
        return None  # column drift: refuse to guess uid/inode positions
    try:
        local_ip, local_port = split_address(parts[1])
        remote_ip, remote_port = split_address(parts[2])
        state_code = parts[3].upper()
        uid = int(parts[7])
        inode = int(parts[9])
    except (ValueError, IndexError):
        return None
    if proto.startswith("udp"):
        # UDP is connectionless; the kernel still prints a "st" column
        # (usually 07) but it carries no TCP-style meaning.
        state = "STATELESS"
    else:
        state = TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
    return Connection(
        proto=proto,
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        state=state,
        uid=uid,
        inode=inode,
    )


def read_proc_net_file(path: str, proto: str) -> tuple[list[Connection], int]:
    """Read one /proc/net/* file.

    Returns (connections, malformed_lines). The header line is skipped
    silently; any other unparsable data line is counted so callers can
    report format drift instead of hiding it.
    """
    connections: list[Connection] = []
    malformed = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "sl":
                continue  # header, not data
            conn = parse_proc_net_line(line, proto)
            if conn is None:
                malformed += 1
            else:
                connections.append(conn)
    return connections, malformed


def get_connections(proc_root: str = DEFAULT_PROC_ROOT) -> tuple[list[Connection], list[str]]:
    """Collect connections from all known /proc/net files.

    Returns (connections, warnings). Raises NetwatchError if nothing
    could be read at all (e.g. not running on Linux).
    """
    connections: list[Connection] = []
    warnings: list[str] = []
    read_any = False
    for filename, proto in PROC_NET_FILES:
        path = os.path.join(proc_root, "net", filename)
        try:
            conns, malformed = read_proc_net_file(path, proto)
        except FileNotFoundError:
            warnings.append(f"{path} not present; skipping {proto}.")
            continue
        except OSError as exc:
            warnings.append(f"could not read {path}: {exc}; skipping {proto}.")
            continue
        read_any = True
        if malformed:
            warnings.append(
                f"skipped {malformed} malformed line(s) in {path}; "
                f"the kernel's {proto} table format may have changed."
            )
        connections.extend(conns)
    if not read_any:
        raise NetwatchError(
            f"could not read any socket tables under {proc_root}/net. "
            "netwatch needs a Linux /proc filesystem."
        )
    return connections, warnings


# ---------------------------------------------------------------------------
# Socket -> process attribution via /proc/<pid>/fd
# ---------------------------------------------------------------------------

_UNSAFE_NAME_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MAX_NAME_LEN = 32


def clean_process_name(name: str) -> str:
    """Neutralize a kernel-reported process name for safe terminal display.

    comm/cmdline content is attacker-influenced: any local process can set
    it, including embedded newlines (table-row forgery) and ANSI escapes
    (terminal manipulation). Replace C0/C1 controls, collapse all
    whitespace runs to single spaces, and truncate: content is preserved,
    control is not.
    """
    cleaned = _UNSAFE_NAME_RE.sub("?", name)
    cleaned = " ".join(cleaned.split())
    return cleaned[:_MAX_NAME_LEN] or "?"


def process_name(proc_root: str, pid: int) -> str:
    """Best-effort process name: /proc/<pid>/comm, else cmdline, else pid."""
    try:
        with open(os.path.join(proc_root, str(pid), "comm"),
                  "r", encoding="utf-8", errors="replace") as handle:
            name = handle.read().strip()
        if name:
            return clean_process_name(name)
    except OSError:
        pass
    try:
        with open(os.path.join(proc_root, str(pid), "cmdline"),
                  "rb") as handle:
            first = handle.read().split(b"\0")[0].decode("utf-8", "replace").strip()
        if first:
            return clean_process_name(os.path.basename(first))
    except OSError:
        pass
    return f"pid {pid}"


def build_inode_map(proc_root: str = DEFAULT_PROC_ROOT) -> tuple[dict[int, list[SocketOwner]], int]:
    """Map socket inode -> owning processes by scanning /proc/<pid>/fd.

    Each open file descriptor that refers to a socket shows up as a symlink
    like 'socket:[12345]', where 12345 is the same inode number listed in
    /proc/net/tcp. That shared inode is the rendezvous key.

    Returns (mapping, unreadable_pids). PIDs whose fd directory cannot be
    read (other users' processes, kernel threads, races with exiting
    processes) are counted, not fatal.
    """
    mapping: dict[int, list[SocketOwner]] = collections.defaultdict(list)
    unreadable = 0
    try:
        entries = os.listdir(proc_root)
    except OSError as exc:
        raise NetwatchError(f"cannot list {proc_root}: {exc}") from exc
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        fd_dir = os.path.join(proc_root, entry, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            unreadable += 1
            continue
        name: str | None = None
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue  # fd vanished between listdir and readlink
            match = _SOCKET_RE.match(target)
            if match:
                if name is None:
                    name = process_name(proc_root, pid)
                mapping[int(match.group(1))].append(SocketOwner(pid=pid, name=name))
    return dict(mapping), unreadable


def attribute_owners(
    connections: list[Connection],
    inode_map: dict[int, list[SocketOwner]],
) -> list[OwnedConnection]:
    """Attach best-effort owner info to each connection."""
    return [
        OwnedConnection(connection=conn, owners=list(inode_map.get(conn.inode, [])))
        for conn in connections
    ]


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def _ip_kind(ip: str) -> str:
    """Rough, informational address classification (never a verdict)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_unspecified:
        return "wildcard"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    if addr.is_global:
        return "public"
    return "other"


def is_listening(conn: Connection) -> bool:
    return conn.state == "LISTEN"


def _remote_is_zero(conn: Connection) -> bool:
    """True when the remote endpoint is unspecified/zero (0.0.0.0:0 or [::]:0)."""
    if conn.remote_port != 0 or not _is_ip(conn.remote_ip):
        return False
    return ipaddress.ip_address(conn.remote_ip).is_unspecified


def is_peerless_udp(conn: Connection) -> bool:
    """UDP with no concrete remote: a listener candidate, not a proven service."""
    return conn.proto.startswith("udp") and _remote_is_zero(conn)


def is_peered_udp(conn: Connection) -> bool:
    """UDP with a concrete remote. Direction (client/server) is not established."""
    return conn.proto.startswith("udp") and not _remote_is_zero(conn)


def is_service(conn: Connection) -> bool:
    """TCP listeners, plus peerless UDP (listener candidates).

    UDP has no LISTEN state. A zero remote (0.0.0.0:0 / [::]:0) is a
    listener candidate; a concrete peer is not a service and does not
    establish inbound reachability.
    """
    return is_listening(conn) or is_peerless_udp(conn)


def is_established(conn: Connection) -> bool:
    return (
        conn.state == "ESTABLISHED"
        and not (ipaddress.ip_address(conn.remote_ip).is_unspecified
                 if _is_ip(conn.remote_ip) else False)
        and conn.remote_port != 0
    )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def owner_label(owners: list[SocketOwner]) -> str:
    if not owners:
        return "? (unattributed)"
    return ", ".join(f"{o.name} [{o.pid}]" for o in owners)


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

def format_table(headers: list[str], rows: list[list[str]]) -> str:
    """Minimal left-aligned table formatter (no dependencies)."""
    # Bound both passes to the header count: extra cells must not IndexError
    # on widths, and missing cells stay absent (no invented blanks).
    col_count = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row[:col_count]):
            widths[i] = max(widths[i], len(cell))
    lines = [
        "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip(),
        "  ".join("-" * widths[i] for i in range(len(headers))).rstrip(),
    ]
    for row in rows:
        lines.append("  ".join(
            cell.ljust(widths[i]) for i, cell in enumerate(row[:col_count])
        ).rstrip())
    return "\n".join(lines)


def endpoint(ip: str, port: int) -> str:
    if ":" in ip:  # IPv6
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def render_connections(conns: list[Connection]) -> str:
    tcp_listen = [c for c in conns if c.proto.startswith("tcp") and is_listening(c)]
    tcp_conn = [c for c in conns if c.proto.startswith("tcp") and not is_listening(c)]
    udp = [c for c in conns if c.proto.startswith("udp")]
    out: list[str] = []
    out.append(f"TCP listening sockets ({len(tcp_listen)}):")
    if tcp_listen:
        out.append(format_table(
            ["PROTO", "LOCAL", "STATE", "UID", "INODE"],
            [[c.proto, endpoint(c.local_ip, c.local_port), c.state,
              str(c.uid), str(c.inode)] for c in tcp_listen],
        ))
    else:
        out.append("  (none observed)")
    out.append(f"\nTCP connected/transient sockets ({len(tcp_conn)}):")
    if tcp_conn:
        out.append(format_table(
            ["PROTO", "LOCAL", "REMOTE", "STATE", "UID", "INODE"],
            [[c.proto, endpoint(c.local_ip, c.local_port),
              endpoint(c.remote_ip, c.remote_port), c.state,
              str(c.uid), str(c.inode)] for c in tcp_conn],
        ))
    else:
        out.append("  (none observed)")
    out.append(f"\nUDP endpoints - connectionless, no state ({len(udp)}):")
    if udp:
        out.append(format_table(
            ["PROTO", "LOCAL", "REMOTE", "UID", "INODE"],
            [[c.proto, endpoint(c.local_ip, c.local_port),
              endpoint(c.remote_ip, c.remote_port),
              str(c.uid), str(c.inode)] for c in udp],
        ))
    else:
        out.append("  (none observed)")
    return "\n".join(out)


def render_processes(records: list[OwnedConnection], unreadable_pids: int) -> str:
    out: list[str] = []
    rows = [
        [r.connection.proto,
         endpoint(r.connection.local_ip, r.connection.local_port),
         endpoint(r.connection.remote_ip, r.connection.remote_port),
         r.connection.state,
         owner_label(r.owners)]
        for r in records
    ]
    out.append(f"Socket-to-process attribution ({len(records)} sockets):")
    if rows:
        out.append(format_table(["PROTO", "LOCAL", "REMOTE", "STATE", "PROCESS"], rows))
    else:
        out.append("  (no sockets observed)")
    unattributed = sum(1 for r in records if not r.owners)
    out.append("")
    out.append(f"{unattributed} socket(s) could not be attributed to a process.")
    if unattributed or unreadable_pids:
        out.append(
            f"{unreadable_pids} process fd directory(ies) were unreadable. "
            "Unreadability does not identify a socket owner "
            "(see `netwatch explain`)."
        )
    return "\n".join(out)


@dataclass
class Summary:
    total: int
    by_proto: dict[str, int]
    by_state: dict[str, int]
    listening: list[Connection]      # TCP listeners
    udp_services: list[Connection]   # peerless UDP (listener candidates)
    udp_peered: list[Connection]     # UDP with a concrete remote
    established: list[OwnedConnection]
    processes: list[str]
    unattributed: int
    unusual: list[str]


def find_unusual(records: list[OwnedConnection]) -> list[str]:
    """Local-only heuristics. These are prompts to investigate, not verdicts.

    One note per socket at most: exposure (wildcard vs loopback vs a
    specific interface) and privilege (<1024) are combined into a single
    note so the operator gets signal, not two notes for one fact pattern.
    Wording describes observable exposure only - never a verdict.
    """
    notes: list[str] = []
    for rec in records:
        conn = rec.connection
        who = owner_label(rec.owners)
        if is_service(conn):
            exposure = _ip_kind(conn.local_ip)
            privileged = conn.local_port < 1024
            service = ("listening on" if is_listening(conn)
                       else "UDP listener candidate on")
            where = endpoint(conn.local_ip, conn.local_port)
            if exposure == "wildcard" and privileged:
                notes.append(
                    f"{service} all interfaces on privileged port (<1024): "
                    f"{conn.proto} {where} ({who}) - reachable from the "
                    f"network, not just localhost; "
                    f"check that you expect this service."
                )
            elif exposure == "wildcard":
                notes.append(
                    f"{service} all interfaces: {conn.proto} "
                    f"{where} ({who}) - "
                    "reachable from the network, not just localhost."
                )
            elif privileged and exposure == "loopback":
                notes.append(
                    f"privileged port (<1024) on loopback only: {conn.proto} "
                    f"{where} ({who}) - reachable only from this machine, "
                    f"not from the network; check that you expect this "
                    f"service."
                )
            elif privileged:
                kind = ("privileged port listening (<1024)"
                        if is_listening(conn)
                        else "privileged UDP port (<1024)")
                notes.append(
                    f"{kind}: {conn.proto} "
                    f"{where} ({who}) - "
                    "check that you expect this service."
                )
            elif exposure != "loopback":
                # Non-loopback specific bind (LAN/bridge/link-local/public).
                # /proc proves the address, not routing or firewall.
                notes.append(
                    f"{service} specific address: {conn.proto} "
                    f"{where} ({who}) - may be reachable from hosts that "
                    f"can route to this address; firewall/routing/interface "
                    f"state not checked; check that you expect this binding."
                )
        if conn.state == "ESTABLISHED" and not rec.owners:
            notes.append(
                f"established connection with unknown owner: "
                f"{endpoint(conn.local_ip, conn.local_port)} -> "
                f"{endpoint(conn.remote_ip, conn.remote_port)} - "
                "process attribution unavailable."
            )
    time_wait = sum(1 for r in records if r.connection.state == "TIME_WAIT")
    if time_wait > 20:
        notes.append(
            f"{time_wait} sockets in TIME_WAIT - usually harmless churn "
            "(recently closed connections), but a large persistent number "
            "is worth understanding."
        )
    return notes


def build_summary(records: list[OwnedConnection]) -> Summary:
    by_proto: dict[str, int] = dict(collections.Counter(r.connection.proto for r in records))
    by_state: dict[str, int] = dict(collections.Counter(r.connection.state for r in records))
    listening = [r.connection for r in records if is_listening(r.connection)]
    udp_services = [r.connection for r in records
                    if is_peerless_udp(r.connection)]
    udp_peered = [r.connection for r in records
                  if is_peered_udp(r.connection)]
    established = [r for r in records if r.connection.state == "ESTABLISHED"]
    processes = sorted({o.name for r in records for o in r.owners})
    unattributed = sum(1 for r in records if not r.owners)
    return Summary(
        total=len(records),
        by_proto=by_proto,
        by_state=by_state,
        listening=listening,
        udp_services=udp_services,
        udp_peered=udp_peered,
        established=established,
        processes=processes,
        unattributed=unattributed,
        unusual=find_unusual(records),
    )


def render_summary(summary: Summary) -> str:
    out: list[str] = [f"Observed {summary.total} socket(s).", ""]
    out.append("Counts by protocol:")
    for proto in sorted(summary.by_proto):
        out.append(f"  {proto}: {summary.by_proto[proto]}")
    out.append("Counts by state:")
    for state in sorted(summary.by_state):
        out.append(f"  {state}: {summary.by_state[state]}")
    out.append(f"\nListening ports - TCP only ({len(summary.listening)}):")
    if summary.listening:
        out.append(format_table(
            ["PROTO", "LOCAL", "UID", "INODE"],
            [[c.proto, endpoint(c.local_ip, c.local_port),
              str(c.uid), str(c.inode)] for c in summary.listening],
        ))
    else:
        out.append("  (none)")
    out.append(f"\nUDP listener candidates - peerless, no listen state "
               f"({len(summary.udp_services)}):")
    if summary.udp_services:
        out.append(format_table(
            ["PROTO", "LOCAL", "UID", "INODE"],
            [[c.proto, endpoint(c.local_ip, c.local_port),
              str(c.uid), str(c.inode)] for c in summary.udp_services],
        ))
    else:
        out.append("  (none)")
    out.append(f"\nPeered UDP endpoints - concrete remote, direction unknown "
               f"({len(summary.udp_peered)}):")
    if summary.udp_peered:
        out.append(format_table(
            ["PROTO", "LOCAL", "REMOTE", "UID", "INODE"],
            [[c.proto, endpoint(c.local_ip, c.local_port),
              endpoint(c.remote_ip, c.remote_port),
              str(c.uid), str(c.inode)] for c in summary.udp_peered],
        ))
    else:
        out.append("  (none)")
    out.append(f"\nEstablished remote connections ({len(summary.established)}):")
    if summary.established:
        rows = []
        for rec in summary.established:
            conn = rec.connection
            rows.append([conn.proto,
                         endpoint(conn.local_ip, conn.local_port),
                         endpoint(conn.remote_ip, conn.remote_port),
                         _ip_kind(conn.remote_ip),
                         owner_label(rec.owners)])
        out.append(format_table(["PROTO", "LOCAL", "REMOTE", "REMOTE-KIND", "PROCESS"], rows))
    else:
        out.append("  (none)")
    out.append(f"\nProcesses involved ({len(summary.processes)}): "
               + (", ".join(summary.processes) if summary.processes else "(none identified)"))
    out.append(f"Unattributed sockets: {summary.unattributed}")
    out.append("\nAnything unusual (local heuristics only - prompts, not verdicts):")
    if summary.unusual:
        for note in summary.unusual:
            out.append(f"  - {note}")
    else:
        out.append("  Nothing stood out. (Absence of flags is not proof of safety.)")
    return "\n".join(out)


EXPLAIN_TEXT = """\
netwatch explain - the concepts behind the output
=================================================

LOCAL vs REMOTE ADDRESS
  Every row has a LOCAL endpoint (your machine's IP + port) and a REMOTE
  endpoint (the other side's IP + port). A connection is just two endpoints
  talking to each other. If REMOTE is 0.0.0.0:0 (or :::0), there is no other
  side yet - that row is a LISTENING socket waiting for someone to connect.

LISTENING SOCKETS
  A listening socket says "I accept new connections on this port". Servers
  create them; e.g. an SSH server listens on port 22. A listener bound to
  127.0.0.1 accepts only connections from your own machine, while one bound
  to 0.0.0.0 (IPv4) or :: (IPv6) - the "wildcard" - accepts connections from
  any network interface, i.e. potentially from other machines.

TCP STATES (the important ones)
  LISTEN       Waiting for incoming connections.
  SYN_SENT     You sent a connection request, awaiting a reply.
  SYN_RECV     You received a request, handshake in progress.
  ESTABLISHED  The connection is open and data can flow. This is the state
               that means real communication is (or was recently) happening.
  FIN_WAIT1/2, CLOSE_WAIT, LAST_ACK, CLOSING
               The two sides are shutting the connection down; each state is
               one step of the goodbye handshake. CLOSE_WAIT hanging around
               can mean the local program forgot to close its socket.
  TIME_WAIT    Fully closed; the kernel keeps the record briefly to stop old
               duplicate packets confusing future connections. Common and
               usually harmless.
  CLOSE        No real connection (often what UDP rows would map to).
  UDP has no states at all - it is connectionless, so netwatch shows
  "STATELESS" for UDP rows. A zero remote (0.0.0.0:0 or [::]:0) is a
  listener candidate, not proof the application accepts datagrams. A
  concrete remote is a peered endpoint; /proc does not establish
  direction (client vs server, inbound vs outbound).

/proc/net/tcp (and tcp6, udp, udp6)
  These are plain-text tables published by the kernel. Each line is one
  socket: local address, remote address, state, user id, and inode number.
  Addresses look odd - e.g. 0100007F:0035 - because the IP is hexadecimal
  with bytes in reverse (little-endian host) order: 01 00 00 7F reversed is
  7F 00 00 01 = 127.0.0.1, and 0035 hex = port 53. IPv6 lines hold 32 hex
  digits with the same per-4-byte reversal. netwatch decodes all of this;
  see decode_hex_ip() in the source.

/proc/<pid>/fd AND THE INODE TRICK
  Every open file - including a network socket - appears as a numbered entry
  under /proc/<pid>/fd/. For sockets the symlink target looks like
  "socket:[12345]". That number is the socket's inode, and it is the SAME
  number shown in the inode column of /proc/net/tcp. So attribution is a
  join: read the socket tables, scan every process's fd directory, and match
  the inode numbers. No special privileges are needed for YOUR OWN processes.

WHY UNPRIVILEGED PROCESSES CANNOT ALWAYS IDENTIFY SOCKET OWNERS
  Linux discretionary access control: /proc/<pid>/fd/ of another user's
  process is unreadable to you (you get PermissionError), so sockets owned
  by root or other users show up as unattributed. Additional causes: kernel
  threads own no user-visible fds; a process may exit between the socket
  scan and the fd scan (a race); containers/network namespaces have their
  own socket tables, so a host-wide read may not see (or may misattribute)
  container sockets; and some systems mount /proc with hidepid=2, which
  hides other users' processes entirely. That is why netwatch reports
  "unattributed" counts instead of guessing. Unattributed means no
  matching readable fd was found; it does not identify the owner or
  the reason attribution failed.
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netwatch",
        description="Defensive Linux network observer: inspect your own "
                    "machine's sockets using /proc. Read-only, no root, "
                    "no network access, no scanning of other machines.",
    )
    parser.add_argument("--version", action="store_true",
                        help="print version and exit")
    parser.add_argument("--proc-root", default=DEFAULT_PROC_ROOT,
                        help="root of the proc filesystem (default: /proc; "
                             "mainly useful for testing)")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.add_parser("connections",
                   help="show observed TCP/UDP sockets (listening vs connected)")
    sub.add_parser("processes",
                   help="show processes associated with sockets (best effort)")
    sub.add_parser("summary",
                   help="security-oriented overview with local-only heuristics")
    sub.add_parser("explain",
                   help="explain the fields and Linux concepts involved")
    return parser


def warn(warnings: list[str]) -> None:
    for message in warnings:
        print(f"netwatch: warning: {message}", file=sys.stderr)


def cmd_connections(proc_root: str) -> int:
    try:
        conns, warnings = get_connections(proc_root)
    except NetwatchError as exc:
        print(f"netwatch: error: {exc}", file=sys.stderr)
        return 1
    warn(warnings)
    print(render_connections(conns))
    return 0


def cmd_processes(proc_root: str) -> int:
    try:
        conns, warnings = get_connections(proc_root)
    except NetwatchError as exc:
        print(f"netwatch: error: {exc}", file=sys.stderr)
        return 1
    try:
        inode_map, unreadable = build_inode_map(proc_root)
    except NetwatchError as exc:
        print(f"netwatch: error: {exc}", file=sys.stderr)
        return 1
    warn(warnings)
    print(render_processes(attribute_owners(conns, inode_map), unreadable))
    return 0


def cmd_summary(proc_root: str) -> int:
    try:
        conns, warnings = get_connections(proc_root)
    except NetwatchError as exc:
        print(f"netwatch: error: {exc}", file=sys.stderr)
        return 1
    try:
        inode_map, _unreadable = build_inode_map(proc_root)
    except NetwatchError as exc:
        print(f"netwatch: error: {exc}", file=sys.stderr)
        return 1
    warn(warnings)
    print(render_summary(build_summary(attribute_owners(conns, inode_map))))
    return 0


def main(argv: list[str] | None = None) -> int:
    restore_sigpipe()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"netwatch {VERSION}")
        code = 0
    elif args.command == "connections":
        code = cmd_connections(args.proc_root)
    elif args.command == "processes":
        code = cmd_processes(args.proc_root)
    elif args.command == "summary":
        code = cmd_summary(args.proc_root)
    elif args.command == "explain":
        print(EXPLAIN_TEXT)
        code = 0
    else:
        parser.print_help()
        code = 0
    try:
        # Flush here, inside the guarded region: with SIG_DFL restored, a
        # closed pipe kills us by signal (status 141, silent). The except
        # below is only a backstop for platforms without SIGPIPE.
        sys.stdout.flush()
    except BrokenPipeError:
        return _SIGPIPE_STATUS
    return code


if __name__ == "__main__":
    sys.exit(main())
