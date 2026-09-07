"""Unit tests for netwatch (standard library unittest only)."""

import io
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netwatch import (  # noqa: E402
    Connection,
    OwnedConnection,
    SocketOwner,
    attribute_owners,
    build_inode_map,
    build_summary,
    decode_hex_ip,
    decode_hex_port,
    find_unusual,
    EXPLAIN_TEXT,
    format_table,
    get_connections,
    is_established,
    is_listening,
    main,
    owner_label,
    parse_proc_net_line,
    render_processes,
    split_address,
)


def make_conn(**kwargs) -> Connection:
    defaults = dict(
        proto="tcp", local_ip="127.0.0.1", local_port=8080,
        remote_ip="0.0.0.0", remote_port=0, state="LISTEN", uid=1000, inode=1,
    )
    defaults.update(kwargs)
    return Connection(**defaults)


class TestDecodeHexIp(unittest.TestCase):
    def test_ipv4_loopback(self):
        self.assertEqual(decode_hex_ip("0100007F"), "127.0.0.1")

    def test_ipv4_wildcard(self):
        self.assertEqual(decode_hex_ip("00000000"), "0.0.0.0")

    def test_ipv4_regular(self):
        # 59106964 -> reversed 64691059 -> 100.105.16.89
        self.assertEqual(decode_hex_ip("59106964"), "100.105.16.89")

    def test_ipv4_lowercase_accepted(self):
        self.assertEqual(decode_hex_ip("0100007f"), "127.0.0.1")

    def test_ipv6_loopback(self):
        self.assertEqual(
            decode_hex_ip("00000000000000000000000001000000"), "::1"
        )

    def test_ipv6_wildcard(self):
        self.assertEqual(
            decode_hex_ip("00000000000000000000000000000000"), "::"
        )

    def test_ipv6_link_local(self):
        result = decode_hex_ip("000080FE000000008463CF35F1975B32")
        self.assertTrue(result.startswith("fe80::"))

    def test_invalid_hex_raises(self):
        with self.assertRaises(ValueError):
            decode_hex_ip("ZZZZ")

    def test_wrong_length_raises(self):
        with self.assertRaises(ValueError):
            decode_hex_ip("0100")  # 2 bytes: neither v4 nor v6

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            decode_hex_ip("")


class TestDecodeHexPort(unittest.TestCase):
    def test_known_ports(self):
        self.assertEqual(decode_hex_port("0016"), 22)
        self.assertEqual(decode_hex_port("0035"), 53)
        self.assertEqual(decode_hex_port("01BB"), 443)

    def test_zero_and_max(self):
        self.assertEqual(decode_hex_port("0000"), 0)
        self.assertEqual(decode_hex_port("FFFF"), 65535)

    def test_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            decode_hex_port("10000")  # 65536

    def test_non_hex_raises(self):
        with self.assertRaises(ValueError):
            decode_hex_port("GGGG")


class TestSplitAddress(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(split_address("0100007F:0277"), ("127.0.0.1", 631))

    def test_ipv6_rsplit(self):
        ip, port = split_address("00000000000000000000000001000000:0016")
        self.assertEqual((ip, port), ("::1", 22))

    def test_malformed_raises(self):
        with self.assertRaises(ValueError):
            split_address("no-colon-here-at-all"[0:0] or "0100007F")
        with self.assertRaises(ValueError):
            split_address("0100007F:")


class TestParseProcNetLine(unittest.TestCase):
    def test_tcp_listen(self):
        line = ("   3: 0100007F:0277 00000000:0000 0A 00000000:00000000 "
                "00:00000000 00000000     0        0 11918 1 00000000925793f0 100 0 0 10 0")
        conn = parse_proc_net_line(line, "tcp")
        self.assertIsNotNone(conn)
        assert conn is not None
        self.assertEqual(conn.local_ip, "127.0.0.1")
        self.assertEqual(conn.local_port, 631)
        self.assertEqual(conn.remote_ip, "0.0.0.0")
        self.assertEqual(conn.remote_port, 0)
        self.assertEqual(conn.state, "LISTEN")
        self.assertEqual(conn.uid, 0)
        self.assertEqual(conn.inode, 11918)

    def test_tcp_established(self):
        line = (" 1561: 59106964:CD57 7797FB8E:01BB 01 00000000:00000000 "
                "00:00000000 00000000  1000        0 262158 2 00000000cca20930 0")
        conn = parse_proc_net_line(line, "tcp")
        self.assertIsNotNone(conn)
        assert conn is not None
        self.assertEqual(conn.state, "ESTABLISHED")
        self.assertEqual(conn.local_ip, "100.105.16.89")
        self.assertEqual(conn.remote_port, 443)
        self.assertEqual(conn.inode, 262158)

    def test_udp_is_stateless(self):
        line = (" 2295: 010011AC:0035 00000000:0000 07 00000000:00000000 "
                "00:00000000 00000000   974        0 8741 2 00000000e4026c29 0")
        conn = parse_proc_net_line(line, "udp")
        self.assertIsNotNone(conn)
        assert conn is not None
        self.assertEqual(conn.state, "STATELESS")

    def test_unknown_state_code_preserved(self):
        line = ("   0: 00000000:0016 00000000:0000 FF 00000000:00000000 "
                "00:00000000 00000000     0        0 10807")
        conn = parse_proc_net_line(line, "tcp")
        self.assertIsNotNone(conn)
        assert conn is not None
        self.assertEqual(conn.state, "UNKNOWN(FF)")

    def test_header_line_skipped(self):
        header = ("  sl  local_address rem_address   st tx_queue rx_queue tr "
                  "tm->when retrnsmt   uid  timeout inode")
        self.assertIsNone(parse_proc_net_line(header, "tcp"))

    def test_blank_and_short_lines_skipped(self):
        self.assertIsNone(parse_proc_net_line("", "tcp"))
        self.assertIsNone(parse_proc_net_line("   0: 0100007F:0277", "tcp"))

    def test_garbage_line_skipped(self):
        self.assertIsNone(parse_proc_net_line("not a proc line at all", "tcp"))

    def test_bad_inode_skipped(self):
        line = ("   0: 00000000:0016 00000000:0000 0A 00000000:00000000 "
                "00:00000000 00000000     0        0 notanumber")
        self.assertIsNone(parse_proc_net_line(line, "tcp"))


class TestClassification(unittest.TestCase):
    def test_is_listening(self):
        self.assertTrue(is_listening(make_conn(state="LISTEN")))
        self.assertFalse(is_listening(make_conn(state="ESTABLISHED")))
        self.assertFalse(is_listening(make_conn(state="STATELESS")))

    def test_is_established(self):
        self.assertTrue(is_established(make_conn(
            state="ESTABLISHED", remote_ip="93.184.216.34", remote_port=443)))
        self.assertFalse(is_established(make_conn(
            state="ESTABLISHED", remote_ip="0.0.0.0", remote_port=0)))
        self.assertFalse(is_established(make_conn(state="LISTEN")))

    def test_owner_label(self):
        self.assertEqual(owner_label([]), "? (unattributed)")
        self.assertEqual(
            owner_label([SocketOwner(pid=1, name="init")]), "init [1]")
        self.assertEqual(
            owner_label([SocketOwner(pid=1, name="a"), SocketOwner(pid=2, name="b")]),
            "a [1], b [2]")


class FakeProcMixin:
    """Build a fake /proc tree in a temp dir for filesystem tests."""

    def make_fake_proc(self) -> str:
        tmp = tempfile.mkdtemp()
        net = os.path.join(tmp, "net")
        os.mkdir(net)
        with open(os.path.join(net, "tcp"), "w") as handle:
            handle.write(
                "  sl  local_address rem_address   st tx_queue rx_queue tr "
                "tm->when retrnsmt   uid  timeout inode\n"
                "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 "
                "00:00000000 00000000  1000        0 1111\n"
                "   1: 0100007F:1F91 0100007F:1F92 01 00000000:00000000 "
                "00:00000000 00000000  1000        0 2222\n"
            )
        with open(os.path.join(net, "tcp6"), "w") as handle:
            handle.write(
                "  sl  local_address remote_address st tx_queue rx_queue\n"
            )
        for name in ("udp", "udp6"):
            with open(os.path.join(net, name), "w") as handle:
                handle.write("  sl  local_address rem_address   st\n")
        # pid 4242 owns socket inode 1111; pid 9999 owns nothing relevant
        for pid, comm, sockets in (("4242", "myapp\n", ["socket:[1111]"]),
                                   ("9999", "other\n", ["socket:[9999]"]),
                                   ("abcd", "notapid\n", [])):  # non-numeric: skipped
            if not pid.isdigit() and pid == "abcd":
                continue  # non-numeric dir must be ignored; still create it
            pdir = os.path.join(tmp, pid, "fd")
            os.makedirs(pdir)
            with open(os.path.join(tmp, pid, "comm"), "w") as handle:
                handle.write(comm)
            for i, target in enumerate(sockets):
                os.symlink(target, os.path.join(pdir, str(i)))
        os.makedirs(os.path.join(tmp, "abcd"))  # non-pid entry, no fd dir
        return tmp


class TestFilesystem(unittest.TestCase, FakeProcMixin):
    def test_get_connections_from_fake_proc(self):
        conns, warnings = get_connections(self.make_fake_proc())
        self.assertEqual(len(conns), 2)
        self.assertEqual(warnings, [])
        self.assertEqual(conns[0].inode, 1111)
        self.assertEqual(conns[0].state, "LISTEN")
        self.assertEqual(conns[1].state, "ESTABLISHED")

    def test_get_connections_missing_net(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(Exception):
                get_connections(tmp)

    def test_build_inode_map(self):
        inode_map, unreadable = build_inode_map(self.make_fake_proc())
        self.assertIn(1111, inode_map)
        self.assertEqual(inode_map[1111][0].pid, 4242)
        self.assertEqual(inode_map[1111][0].name, "myapp")
        self.assertNotIn(2222, inode_map)  # nobody holds it
        self.assertEqual(unreadable, 0)

    def test_unreadable_fd_dir_counted(self):
        tmp = self.make_fake_proc()
        os.makedirs(os.path.join(tmp, "5555"))  # pid dir without fd dir
        _inode_map, unreadable = build_inode_map(tmp)
        self.assertEqual(unreadable, 1)

    def test_missing_comm_falls_back(self):
        tmp = self.make_fake_proc()
        pdir = os.path.join(tmp, "7777", "fd")
        os.makedirs(pdir)
        os.symlink("socket:[555]", os.path.join(pdir, "0"))
        # no comm file, but cmdline present
        with open(os.path.join(tmp, "7777", "cmdline"), "wb") as handle:
            handle.write(b"/usr/bin/mydaemon\x00--flag\x00")
        inode_map, _ = build_inode_map(tmp)
        self.assertEqual(inode_map[555][0].name, "mydaemon")

    def test_attribute_owners(self):
        tmp = self.make_fake_proc()
        conns, _ = get_connections(tmp)
        inode_map, _ = build_inode_map(tmp)
        records = attribute_owners(conns, inode_map)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].owners[0].name, "myapp")
        self.assertEqual(records[1].owners, [])


class TestSummary(unittest.TestCase):
    def test_build_summary_counts(self):
        records = [
            OwnedConnection(make_conn(proto="tcp", state="LISTEN", inode=1),
                            [SocketOwner(100, "web")]),
            OwnedConnection(make_conn(proto="tcp", state="ESTABLISHED",
                                       remote_ip="93.184.216.34",
                                       remote_port=443, inode=2), []),
            OwnedConnection(make_conn(proto="udp", state="STATELESS",
                                       local_ip="0.0.0.0", local_port=53,
                                       inode=3), []),
        ]
        summary = build_summary(records)
        self.assertEqual(summary.total, 3)
        self.assertEqual(summary.by_proto, {"tcp": 2, "udp": 1})
        self.assertEqual(summary.by_state["LISTEN"], 1)
        self.assertEqual(len(summary.listening), 1)
        self.assertEqual(len(summary.established), 1)
        self.assertEqual(summary.processes, ["web"])
        self.assertEqual(summary.unattributed, 2)

    def test_find_unusual_flags_wildcard_listener(self):
        rec = OwnedConnection(
            make_conn(state="LISTEN", local_ip="0.0.0.0", local_port=8080,
                      inode=1), [SocketOwner(100, "web")])
        notes = find_unusual([rec])
        self.assertTrue(any("all interfaces" in n for n in notes))

    def test_find_unusual_quiet_for_loopback_listener(self):
        rec = OwnedConnection(
            make_conn(state="LISTEN", local_ip="127.0.0.1", local_port=8080,
                      inode=1), [SocketOwner(100, "web")])
        self.assertEqual(find_unusual([rec]), [])

    def test_find_unusual_flags_privileged_port(self):
        rec = OwnedConnection(
            make_conn(state="LISTEN", local_ip="127.0.0.1", local_port=22,
                      inode=1), [SocketOwner(1, "sshd")])
        notes = find_unusual([rec])
        self.assertTrue(any("privileged" in n for n in notes))

    def test_find_unusual_flags_unknown_owner_established(self):
        rec = OwnedConnection(
            make_conn(state="ESTABLISHED", local_ip="10.0.0.5", local_port=50000,
                      remote_ip="93.184.216.34", remote_port=443, inode=2), [])
        notes = find_unusual([rec])
        self.assertTrue(any("unknown owner" in n for n in notes))

    def test_find_unusual_time_wait_churn(self):
        records = [OwnedConnection(make_conn(state="TIME_WAIT", inode=i), [])
                   for i in range(25)]
        notes = find_unusual(records)
        self.assertTrue(any("TIME_WAIT" in n for n in notes))
        few = [OwnedConnection(make_conn(state="TIME_WAIT", inode=i), [])
               for i in range(3)]
        self.assertEqual(find_unusual(few), [])


class TestFormatTable(unittest.TestCase):
    def test_basic_alignment(self):
        out = format_table(["A", "BB"], [["x", "y"], ["longer", "z"]])
        lines = out.splitlines()
        self.assertEqual(len(lines), 4)  # header, separator, 2 rows
        self.assertTrue(all(len(line) > 0 for line in lines))


class TestCli(unittest.TestCase, FakeProcMixin):
    def run_main(self, *args: str) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(list(args))
        return code, buf.getvalue()

    def test_explain(self):
        code, out = self.run_main("explain")
        self.assertEqual(code, 0)
        for keyword in ("LISTEN", "/proc/net/tcp", "/proc/<pid>/fd",
                        "inode", "ESTABLISHED"):
            self.assertIn(keyword, out)

    def test_connections_against_fake_proc(self):
        code, out = self.run_main("--proc-root", self.make_fake_proc(),
                                  "connections")
        self.assertEqual(code, 0)
        self.assertIn("listening", out.lower())
        self.assertIn("127.0.0.1:8080", out)

    def test_processes_against_fake_proc(self):
        code, out = self.run_main("--proc-root", self.make_fake_proc(),
                                  "processes")
        self.assertEqual(code, 0)
        self.assertIn("myapp [4242]", out)
        self.assertIn("unattributed", out.lower())

    def test_summary_against_fake_proc(self):
        code, out = self.run_main("--proc-root", self.make_fake_proc(),
                                  "summary")
        self.assertEqual(code, 0)
        self.assertIn("Listening ports", out)
        self.assertIn("Established", out)

    def test_no_command_prints_help(self):
        code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("usage", out.lower())

    def test_bad_proc_root_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--proc-root", tmp, "summary"])
            self.assertEqual(code, 1)


class TestAdversarial(unittest.TestCase):
    """Hostile-review regression tests (H1, M1, M2, M3).

    Each test in this class fails against netwatch v0.1.0 and passes only
    after the corresponding fix. They must never be weakened to make a
    future change pass.
    """

    NETWATCH_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    IPV4_HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr "
                   "tm->when retrnsmt   uid  timeout inode\n")

    def _make_proc_root(self, net_files, pids=()):
        """Build a fake /proc tree. net_files maps filename->data lines
        (headers added automatically); pids maps pid->(comm_bytes|None,
        cmdline_bytes|None, [fd targets])."""
        tmp = tempfile.mkdtemp()
        net = os.path.join(tmp, "net")
        os.mkdir(net)
        for name in ("tcp", "tcp6", "udp", "udp6"):
            with open(os.path.join(net, name), "w") as handle:
                handle.write(self.IPV4_HEADER)
                for line in net_files.get(name, []):
                    handle.write(line)
        for pid, comm, cmdline, targets in pids:
            pdir = os.path.join(tmp, pid, "fd")
            os.makedirs(pdir)
            if comm is not None:
                with open(os.path.join(tmp, pid, "comm"), "wb") as handle:
                    handle.write(comm)
            if cmdline is not None:
                with open(os.path.join(tmp, pid, "cmdline"), "wb") as handle:
                    handle.write(cmdline)
            for i, target in enumerate(targets):
                os.symlink(target, os.path.join(pdir, str(i)))
        return tmp

    # -- H1: UDP services must be visible and flagged ---------------------
    def test_udp_wildcard_service_is_surfaced(self):
        tmp = self._make_proc_root({
            "udp": ["  10: 00000000:0035 00000000:0000 07 00000000:00000000 "
                    "00:00000000 00000000     0        0 5555\n"],
        })
        conns, warnings = get_connections(tmp)
        self.assertEqual(warnings, [])
        self.assertEqual(len(conns), 1)
        summary = build_summary(attribute_owners(conns, {}))
        # The UDP service must appear as a service, not vanish into counts.
        self.assertEqual(len(summary.udp_services), 1)
        self.assertEqual(summary.udp_services[0].local_port, 53)
        # ... and the wildcard exposure must be flagged.
        notes = [n for n in summary.unusual if "udp" in n.lower()]
        self.assertTrue(notes, "UDP wildcard service produced no note")
        self.assertTrue(any("53" in n and "all interfaces" in n for n in notes))

    # -- M1: hostile process names must not forge output ------------------
    def test_hostile_process_name_cannot_forge_rows(self):
        hostile_comm = b"evil\nFORGED 9.9.9.9:1 x\n\x1b[2J"
        hostile_cmd = b"/usr/bin/evil\nprog\x1b[31m\x00--flag\x00"
        long_cmd = b"/usr/bin/" + b"A" * 200 + b"\x00"
        tmp = self._make_proc_root(
            {"tcp": ["   0: 00000000:0016 00000000:0000 0A 00000000:00000000 "
                     "00:00000000 00000000     0        0 777\n"]},
            pids=[("1234", hostile_comm, None, ["socket:[777]"]),
                  ("5678", None, hostile_cmd, ["socket:[777]"]),
                  ("9012", None, long_cmd, ["socket:[777]"])],
        )
        inode_map, _ = build_inode_map(tmp)
        names = [o.name for o in inode_map[777]]
        self.assertEqual(len(names), 3)
        for name in names:
            self.assertNotIn("\n", name)
            self.assertNotIn("\x1b", name)
            self.assertLessEqual(len(name), 32)
        self.assertTrue(any("FORGED" in n for n in names),
                        "legitimate content should survive, neutralized")
        conns, _ = get_connections(tmp)
        out = render_processes(attribute_owners(conns, inode_map), 0)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\nFORGED", out)

    # -- M2: corrupt columns must not silently misparse -------------------
    def test_garbage_queue_column_is_rejected(self):
        good = ("   0: 00000000:0016 00000000:0000 0A 00000000:00000000 "
                "00:00000000 00000000     0        0 10807\n")
        bad = good.replace("00000000:00000000", "ZZZ", 1)
        self.assertIsNotNone(parse_proc_net_line(good, "tcp"))
        self.assertIsNone(parse_proc_net_line(bad, "tcp"),
                          "line with corrupt queue column must be skipped, "
                          "not parsed")

    def test_malformed_lines_produce_a_warning(self):
        tmp = self._make_proc_root({
            "tcp": ["   0: 00000000:0016 00000000:0000 0A 00000000:00000000 "
                    "00:00000000 00000000     0        0 10807\n",
                    "   1: 00000000:0017 00000000:0000 0A 00000000:00000000 "
                    "00:00000000 00000000     0        0 notanumber\n"],
        })
        conns, warnings = get_connections(tmp)
        self.assertEqual(len(conns), 1)
        self.assertTrue(any("malformed" in w for w in warnings),
                        f"format drift must be visible; got: {warnings}")

    def test_tcp6_data_line_parses(self):
        line = ("   0: 00000000000000000000000001000000:0016 "
                "00000000000000000000000000000000:0000 0A "
                "00000000:00000000 00:00000000 00000000     0        0 10809")
        conn = parse_proc_net_line(line, "tcp6")
        self.assertIsNotNone(conn)
        assert conn is not None
        self.assertEqual((conn.local_ip, conn.local_port), ("::1", 22))
        self.assertEqual(conn.state, "LISTEN")

    # -- M3: dying on a closed pipe must be silent and conventional -------
    def test_broken_pipe_dies_by_sigpipe(self):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)  # no reader will ever exist: first write must fail
        try:
            proc = subprocess.Popen(
                [sys.executable,
                 os.path.join(self.NETWATCH_DIR, "netwatch.py"), "explain"],
                stdout=write_fd, stderr=subprocess.DEVNULL)
        finally:
            os.close(write_fd)
        self.assertEqual(proc.wait(), -signal.SIGPIPE)


class TestL1Signal(unittest.TestCase):
    """Backlog L1: heuristic notes must prioritize signal over noise.

    One note per socket (no wildcard+privileged double-flagging), and
    loopback-only privileged listeners must read as less exposed than
    wildcard ones while still preserving the privileged-port fact.
    """

    def test_wildcard_privileged_produces_single_note(self):
        rec = OwnedConnection(
            make_conn(state="LISTEN", local_ip="0.0.0.0", local_port=22,
                      inode=1), [SocketOwner(1, "sshd")])
        notes = find_unusual([rec])
        self.assertEqual(len(notes), 1,
                         f"one socket must yield one note; got: {notes}")
        self.assertIn("all interfaces", notes[0])
        self.assertIn("privileged", notes[0])
        self.assertIn("22", notes[0])

    def test_loopback_privileged_is_distinguished(self):
        rec = OwnedConnection(
            make_conn(state="LISTEN", local_ip="127.0.0.1", local_port=22,
                      inode=1), [SocketOwner(1, "sshd")])
        notes = find_unusual([rec])
        self.assertEqual(len(notes), 1,
                         f"privileged fact must be preserved; got: {notes}")
        self.assertIn("privileged", notes[0])
        self.assertIn("loopback", notes[0])
        self.assertNotIn("all interfaces", notes[0])

    def test_udp_wildcard_privileged_single_note(self):
        rec = OwnedConnection(
            make_conn(proto="udp", state="STATELESS", local_ip="0.0.0.0",
                      local_port=53, inode=3), [])
        notes = find_unusual([rec])
        self.assertEqual(len(notes), 1,
                         f"one socket must yield one note; got: {notes}")
        lowered = notes[0].lower()
        self.assertIn("udp", lowered)
        self.assertIn("53", notes[0])
        self.assertIn("all interfaces", notes[0])
        self.assertIn("privileged", notes[0])

    def test_specific_ip_privileged_keeps_its_note(self):
        # Guard: bound-to-one-interface privileged services must not go
        # silent as a side effect of the merge.
        rec = OwnedConnection(
            make_conn(state="LISTEN", local_ip="172.17.0.1", local_port=53,
                      inode=1), [])
        notes = find_unusual([rec])
        self.assertEqual(len(notes), 1)
        self.assertIn("privileged", notes[0])


class TestL8RaggedRows(unittest.TestCase):
    """Backlog L8: format_table() must not IndexError on ragged rows.

    Column widths are a list sized to the headers. A row with more cells
    than headers currently indexes past that list and crashes the CLI.
    Extra cells must be dropped (no invented columns); missing cells stay
    absent (no invented blanks). Valid rectangular rows stay unchanged.
    """

    # Golden output of the existing TestFormatTable case. Locked so the
    # defensive change cannot drift normal formatting.
    VALID = "A       BB\n------  --\nx       y\nlonger  z"

    def test_valid_rows_byte_for_byte(self):
        out = format_table(["A", "BB"], [["x", "y"], ["longer", "z"]])
        self.assertEqual(out, self.VALID)

    def test_zero_rows(self):
        out = format_table(["A", "BB"], [])
        self.assertEqual(out, "A  BB\n-  --")

    def test_one_valid_row(self):
        out = format_table(["A", "BB"], [["x", "y"]])
        self.assertEqual(out, "A  BB\n-  --\nx  y")

    def test_empty_row_does_not_invent_cells(self):
        out = format_table(["A", "BB"], [[]])
        self.assertEqual(out, "A  BB\n-  --\n")

    def test_short_row_does_not_invent_cells(self):
        out = format_table(["A", "BB"], [["only"]])
        self.assertEqual(out, "A     BB\n----  --\nonly")

    def test_row_longer_than_headers_does_not_crash(self):
        out = format_table(["A", "BB"], [["x", "y", "EXTRA_CELL"]])
        self.assertEqual(out, "A  BB\n-  --\nx  y")
        self.assertNotIn("EXTRA_CELL", out)

    def test_extra_cells_do_not_change_valid_columns(self):
        valid = [["x", "y"], ["aa", "bb"]]
        ragged = [["x", "y"], ["aa", "bb", "EXTRA_CELL"]]
        self.assertEqual(
            format_table(["A", "B"], ragged),
            format_table(["A", "B"], valid),
        )

    def test_mixed_ragged_rows_do_not_crash(self):
        out = format_table(
            ["A", "B", "C"],
            [
                ["1", "2", "3"],
                ["only"],
                [],
                ["a", "b", "c", "EXTRA_CELL"],
            ],
        )
        self.assertIn("1", out)
        self.assertIn("2", out)
        self.assertIn("3", out)
        self.assertIn("only", out)
        self.assertNotIn("EXTRA_CELL", out)
        self.assertEqual(len(out.splitlines()), 6)  # header, sep, 4 data rows


class TestL2AttributionLanguage(unittest.TestCase):
    """Backlog L2: attribution wording must not exceed collected evidence.

    A missing inode join is 'unattributed' / 'process attribution
    unavailable'. It does not establish another-user ownership, intent,
    or a specific cause. Existing TestSummary assertions stay intact:
    they already require the 'unknown owner' flag, not the causal clause.
    """

    def _unattributed_established(self) -> OwnedConnection:
        return OwnedConnection(
            make_conn(state="ESTABLISHED", local_ip="10.0.0.5",
                      local_port=50000, remote_ip="93.184.216.34",
                      remote_port=443, inode=2), [])

    def test_unattributed_established_does_not_claim_another_user(self):
        notes = find_unusual([self._unattributed_established()])
        self.assertEqual(len(notes), 1, f"expected one note; got: {notes}")
        lowered = notes[0].lower()
        self.assertNotIn("another user", lowered)
        self.assertNotIn("likely belongs", lowered)

    def test_unattributed_established_says_attribution_unavailable(self):
        notes = find_unusual([self._unattributed_established()])
        self.assertEqual(len(notes), 1, f"expected one note; got: {notes}")
        self.assertIn("process attribution unavailable", notes[0])
        self.assertIn("10.0.0.5:50000", notes[0])
        self.assertIn("93.184.216.34:443", notes[0])

    def test_attributed_established_is_not_flagged(self):
        rec = OwnedConnection(
            make_conn(state="ESTABLISHED", local_ip="10.0.0.5",
                      local_port=50000, remote_ip="93.184.216.34",
                      remote_port=443, inode=2),
            [SocketOwner(100, "web")])
        self.assertEqual(find_unusual([rec]), [])

    def test_time_wait_inode_zero_is_not_another_user(self):
        rec = OwnedConnection(make_conn(state="TIME_WAIT", inode=0), [])
        blob = "\n".join(find_unusual([rec])).lower()
        self.assertNotIn("another user", blob)
        self.assertNotIn("unknown owner", blob)

    def test_unattributed_privileged_wildcard_uses_unattributed_label(self):
        rec = OwnedConnection(
            make_conn(state="LISTEN", local_ip="0.0.0.0", local_port=22,
                      inode=1), [])
        notes = find_unusual([rec])
        self.assertEqual(len(notes), 1, f"expected one note; got: {notes}")
        self.assertIn("unattributed", notes[0])
        self.assertNotIn("another user", notes[0].lower())

    def test_unattributed_privileged_loopback_uses_unattributed_label(self):
        rec = OwnedConnection(
            make_conn(state="LISTEN", local_ip="127.0.0.1", local_port=631,
                      inode=1), [])
        notes = find_unusual([rec])
        self.assertEqual(len(notes), 1, f"expected one note; got: {notes}")
        self.assertIn("unattributed", notes[0])
        self.assertIn("loopback", notes[0])
        self.assertNotIn("another user", notes[0].lower())

    def test_unattributed_udp_does_not_claim_another_user(self):
        rec = OwnedConnection(
            make_conn(proto="udp", state="STATELESS", local_ip="0.0.0.0",
                      local_port=53, inode=3), [])
        notes = find_unusual([rec])
        blob = "\n".join(notes).lower()
        self.assertTrue(notes)
        self.assertIn("unattributed", blob)
        self.assertNotIn("another user", blob)

    def test_successful_attribution_still_shows_pid_and_name(self):
        rec = OwnedConnection(
            make_conn(state="ESTABLISHED", local_ip="10.0.0.5",
                      local_port=50000, remote_ip="1.2.3.4",
                      remote_port=443, inode=9),
            [SocketOwner(4242, "myapp")])
        self.assertEqual(owner_label(rec.owners), "myapp [4242]")
        out = render_processes([rec], 0)
        self.assertIn("myapp [4242]", out)
        self.assertNotIn("another user", out.lower())

    def test_multiple_owners_are_listed_not_guessed(self):
        rec = OwnedConnection(
            make_conn(state="ESTABLISHED", local_ip="10.0.0.5",
                      local_port=50000, remote_ip="1.2.3.4",
                      remote_port=443, inode=9),
            [SocketOwner(1, "a"), SocketOwner(2, "b")])
        self.assertEqual(owner_label(rec.owners), "a [1], b [2]")
        self.assertEqual(find_unusual([rec]), [])

    def test_render_processes_does_not_invent_a_cause(self):
        out = render_processes([self._unattributed_established()],
                               unreadable_pids=4)
        lowered = out.lower()
        self.assertIn("unreadable", lowered)
        self.assertIn("4", out)
        self.assertNotIn("another user", lowered)
        self.assertNotIn("without root", lowered)
        self.assertNotIn("your own processes", lowered)

    def test_explain_unattributed_is_not_identification(self):
        collapsed = " ".join(EXPLAIN_TEXT.lower().split())
        self.assertIn("unattributed", collapsed)
        self.assertIn(
            "does not identify the owner or the reason attribution failed",
            collapsed,
        )


class TestF1PrivilegedPortEvidence(unittest.TestCase):
    """Finding F1: port <1024 is not proof that a privileged process bound.

    /proc/net/* evidence actually collected for a service row:
      - local_port (and local_ip, proto, state, inode)
      - socket uid (sk_uid), already parsed into Connection.uid
    That does not establish:
      - CAP_NET_BIND_SERVICE or euid 0 was required
      - the current process is privileged
      - net.ipv4.ip_unprivileged_port_start is still 1024
    Live counterexample: a port-53 listener with socket uid 974.
    Keep the conventional '<1024' / 'privileged port' range label (L1);
    drop the universal 'only a privileged process can bind' claim.
    Existing TestL1Signal / TestSummary assertions stay intact.
    """

    def _notes_for(self, **kwargs) -> list[str]:
        return find_unusual([OwnedConnection(make_conn(**kwargs), [])])

    def test_nonroot_uid_on_low_port_does_not_claim_only_privileged_can_bind(self):
        # Same shape as the live docker-dns row: port 53, socket uid 974.
        notes = self._notes_for(
            state="LISTEN", local_ip="172.17.0.1", local_port=53, uid=974)
        self.assertEqual(len(notes), 1, f"expected one note; got: {notes}")
        lowered = notes[0].lower()
        self.assertNotIn("only a privileged process", lowered)
        self.assertNotIn("can bind here", lowered)
        self.assertIn("privileged", lowered)
        self.assertIn("53", notes[0])

    def test_default_fixture_uid_1000_on_port_22_does_not_claim_bind_privilege(self):
        # make_conn defaults uid=1000; L1 still uses that fixture.
        notes = self._notes_for(
            state="LISTEN", local_ip="0.0.0.0", local_port=22)
        self.assertEqual(len(notes), 1, f"expected one note; got: {notes}")
        lowered = notes[0].lower()
        self.assertNotIn("only a privileged process", lowered)
        self.assertNotIn("can bind here", lowered)
        self.assertIn("privileged", lowered)
        self.assertIn("all interfaces", lowered)

    def test_loopback_privileged_note_does_not_claim_bind_privilege(self):
        notes = self._notes_for(
            state="LISTEN", local_ip="127.0.0.1", local_port=631, uid=0)
        self.assertEqual(len(notes), 1, f"expected one note; got: {notes}")
        lowered = notes[0].lower()
        self.assertNotIn("only a privileged process", lowered)
        self.assertNotIn("can bind here", lowered)
        self.assertIn("privileged", lowered)
        self.assertIn("loopback", lowered)

    def test_udp_privileged_note_does_not_claim_bind_privilege(self):
        notes = self._notes_for(
            proto="udp", state="STATELESS", local_ip="0.0.0.0",
            local_port=53, uid=968)
        self.assertEqual(len(notes), 1, f"expected one note; got: {notes}")
        lowered = notes[0].lower()
        self.assertNotIn("only a privileged process", lowered)
        self.assertNotIn("can bind here", lowered)
        self.assertIn("privileged", lowered)

    def test_high_port_wildcard_still_has_no_privileged_bind_claim(self):
        notes = self._notes_for(
            state="LISTEN", local_ip="0.0.0.0", local_port=8080, uid=1000)
        self.assertEqual(len(notes), 1)
        lowered = notes[0].lower()
        self.assertNotIn("privileged", lowered)
        self.assertNotIn("can bind here", lowered)


if __name__ == "__main__":
    unittest.main()
