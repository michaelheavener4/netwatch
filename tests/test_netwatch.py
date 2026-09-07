"""Unit tests for netwatch (standard library unittest only)."""

import io
import os
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
    format_table,
    get_connections,
    is_established,
    is_listening,
    main,
    owner_label,
    parse_proc_net_line,
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


if __name__ == "__main__":
    unittest.main()
