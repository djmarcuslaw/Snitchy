"""Unit tests. Run with:  python3 -m unittest discover -s tests -v"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import builders as b  # noqa: E402
from snitchy import appinfo, packets, pcapng, service  # noqa: E402
from snitchy.capture import Engine, Hub  # noqa: E402
from snitchy.server import make_server  # noqa: E402
from snitchy.store import Store  # noqa: E402
from snitchy import tracker as tracker_mod  # noqa: E402
from snitchy.tracker import Tracker  # noqa: E402

ME = "192.168.1.23"
GOOGLE = "142.250.80.4"


def sample_stream(endian="<"):
    """A tiny capture: Safari looks up and connects to www.google.com over HTTPS,
    then a helper makes a request on behalf of Spotify, and lo0 noise is present."""
    t = 1_700_000_000.0
    out = b.shb(endian)
    out += b.idb(1, "en0", endian)                       # interface 0: Wi-Fi
    out += b.idb(0, "lo0", endian)                       # interface 1: loopback
    out += b.pib(-1, "", endian)                         # pib 0: unknown process
    out += b.pib(412, "Safari", endian)                  # pib 1
    out += b.pib(88, "nsurlsessiond", endian)            # pib 2
    out += b.pib(733, "Spotify", endian)                 # pib 3
    query = b.dns_query("www.google.com")
    out += b.epb(0, t - 0.01, b.ethernet(b.ipv4(ME, "1.1.1.1", 17, b.udp(5353, 53, query))), "out", 0,
                 endian=endian)
    dns = b.dns_response("www.google.com", [GOOGLE])
    out += b.epb(0, t, b.ethernet(b.ipv4("1.1.1.1", ME, 17, b.udp(53, 5353, dns))), "in", 0, endian=endian)
    out += b.epb(0, t + 0.01, b.ethernet(b.ipv4(ME, GOOGLE, 6, b.tcp(50000, 443, packets.SYN))),
                 "out", 1, endian=endian)
    out += b.epb(0, t + 0.02, b.ethernet(b.ipv4(GOOGLE, ME, 6, b.tcp(443, 50000, packets.SYN | packets.ACK))),
                 "in", 1, endian=endian)
    hello = b.client_hello("www.google.com")
    out += b.epb(0, t + 0.03, b.ethernet(b.ipv4(ME, GOOGLE, 6, b.tcp(50000, 443, packets.ACK, hello))),
                 "out", 1, endian=endian)
    # Spotify traffic sent by a system helper (pib 2) on Spotify's behalf (e-pib 3), over IPv6
    out += b.epb(0, t + 0.04, b.ethernet(b.ipv6("fe80::1", "2600::1", 6, b.tcp(50001, 443, packets.SYN)), v6=True),
                 "out", 2, 3, endian=endian)
    # loopback chatter (ignored by default)
    out += b.epb(1, t + 0.05, b.null_link(b.ipv4("127.0.0.1", "127.0.0.1", 6, b.tcp(50002, 8899, packets.SYN))),
                 "out", 1, endian=endian)
    return out


class PcapngTests(unittest.TestCase):
    def test_parses_blocks_and_process_tags(self):
        pkts = pcapng.PcapngStream().feed(sample_stream())
        self.assertEqual(len(pkts), 7)
        syn = pkts[2]
        self.assertEqual(syn.interface.name, "en0")
        self.assertEqual(syn.direction, "out")
        self.assertEqual(syn.process.name, "Safari")
        self.assertEqual(syn.process.pid, 412)
        self.assertAlmostEqual(syn.timestamp, 1_700_000_000.01, places=5)
        self.assertEqual(pkts[0].process.pid, -1)
        self.assertEqual(pkts[5].process.name, "nsurlsessiond")
        self.assertEqual(pkts[5].eprocess.name, "Spotify")

    def test_byte_at_a_time(self):
        """tcpdump output arrives in arbitrary chunks; results must be identical."""
        data = sample_stream()
        stream = pcapng.PcapngStream()
        pkts = []
        for i in range(len(data)):
            pkts.extend(stream.feed(data[i:i + 1]))
        self.assertEqual(len(pkts), 7)
        self.assertEqual(pkts[4].process.name, "Safari")

    def test_big_endian(self):
        pkts = pcapng.PcapngStream().feed(sample_stream(">"))
        self.assertEqual(len(pkts), 7)
        self.assertEqual(pkts[2].process.name, "Safari")

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            pcapng.PcapngStream().feed(b"\x00" * 64)


class PacketTests(unittest.TestCase):
    def test_ipv4_tcp(self):
        seg = packets.parse_segment(1, b.ethernet(b.ipv4(ME, GOOGLE, 6, b.tcp(1234, 443, packets.SYN))))
        self.assertEqual((seg.proto, seg.src, seg.sport, seg.dst, seg.dport), ("tcp", ME, 1234, GOOGLE, 443))
        self.assertTrue(seg.flags & packets.SYN)

    def test_ipv6_udp_over_utun(self):
        seg = packets.parse_segment(0, b.null_link(b.ipv6("fd00::2", "2001:4860::8888", 17, b.udp(5000, 53, b"x")), v6=True))
        self.assertEqual((seg.proto, seg.dst, seg.dport, seg.payload), ("udp", "2001:4860::8888", 53, b"x"))

    def test_raw_ip(self):
        seg = packets.parse_segment(12, b.ipv4(ME, GOOGLE, 17, b.udp(1, 2, b"")))
        self.assertEqual(seg.proto, "udp")

    def test_garbage_is_ignored(self):
        self.assertIsNone(packets.parse_segment(1, b"\x00" * 10))
        self.assertIsNone(packets.parse_segment(999, b"\x45" * 60))

    def test_dns_answers(self):
        name, ips = packets.parse_dns_answers(b.dns_response("example.com", ["93.184.216.34", "2606:2800::1"]))
        self.assertEqual(name, "example.com")
        self.assertEqual(ips, ["93.184.216.34", "2606:2800::1"])

    def test_dns_cname_credits_original_name(self):
        name, ips = packets.parse_dns_answers(
            b.dns_response("www.example.com", ["1.2.3.4"], cname="edge.cdn.example.net"))
        self.assertEqual((name, ips), ("www.example.com", ["1.2.3.4"]))

    def test_dns_query_is_not_an_answer(self):
        query = bytearray(b.dns_response("example.com", []))
        query[2] = 0x01                                     # clear the "response" bit
        self.assertIsNone(packets.parse_dns_answers(bytes(query)))

    def test_sni(self):
        self.assertEqual(packets.parse_tls_sni(b.client_hello("Api.Example.com")), "api.example.com")

    def test_sni_truncated_then_complete(self):
        hello = b.client_hello("big.example.org", padding=1500)
        self.assertIsNone(packets.parse_tls_sni(hello[:1000]))       # wait for more
        self.assertEqual(packets.parse_tls_sni(hello), "big.example.org")

    def test_not_tls(self):
        self.assertEqual(packets.parse_tls_sni(b"GET / HTTP/1.1\r\n"), "")


class TrackerTests(unittest.TestCase):
    def run_sample(self, **kw):
        tracker = Tracker(path_lookup=lambda pid: {412: "/Applications/Safari.app/Contents/MacOS/Safari",
                                                     733: "/Applications/Spotify.app/Contents/MacOS/Spotify"}.get(pid, ""),
                          **kw)
        for pkt in pcapng.PcapngStream().feed(sample_stream()):
            tracker.handle(pkt)
        return tracker

    def test_connection_attribution(self):
        tracker = self.run_sample()
        new, _ = tracker.drain(now=1_700_000_001)
        by_port = {f.remote_port: f for f in new if f.proto == "tcp"}
        safari = [f for f in new if f.app == "Safari"][0]
        self.assertEqual(safari.remote_ip, GOOGLE)
        self.assertEqual(safari.direction, "out")
        self.assertEqual(safari.path, "/Applications/Safari.app")
        self.assertEqual(safari.domain, "www.google.com")
        self.assertEqual(safari.domain_source, "sni")      # upgraded from dns by the HTTPS hello
        self.assertEqual(safari.packets_out, 2)
        self.assertEqual(safari.packets_in, 1)
        spotify = [f for f in new if f.app == "Spotify"][0]
        self.assertEqual(spotify.via, "nsurlsessiond")
        self.assertEqual(spotify.remote_ip, "2600::1")
        self.assertIn(443, by_port)

    def test_loopback_skipped_by_default(self):
        tracker = self.run_sample()
        self.assertFalse(any(f.remote_port == 8899 for f in tracker.flows.values()))
        tracker = self.run_sample(include_loopback=True)
        self.assertTrue(any(f.remote_port == 8899 for f in tracker.flows.values()))

    def test_incoming_connection(self):
        tracker = Tracker(path_lookup=lambda pid: "")
        stream = b.shb() + b.idb(1, "en0") + b.pib(50, "sshd") + \
            b.epb(0, 1.0, b.ethernet(b.ipv4("10.0.0.9", ME, 6, b.tcp(40000, 22, packets.SYN))), "in", 0)
        for pkt in pcapng.PcapngStream().feed(stream):
            tracker.handle(pkt)
        (flow,) = tracker.flows.values()
        self.assertEqual((flow.direction, flow.local_port, flow.remote_ip, flow.app), ("in", 22, "10.0.0.9", "sshd"))

    def test_close_and_expire(self):
        tracker = self.run_sample()
        tracker.drain(now=1)
        for f in tracker.flows.values():
            f.row_id = 1
        safari_key = [k for k, f in tracker.flows.items() if f.app == "Safari"][0]
        flow = tracker.flows[safari_key]
        flow.closed_at = 100.0
        flow.dirty_bytes = True                           # a late packet arrived
        tracker.expire(now=200.0)
        self.assertNotIn(safari_key, tracker.flows)
        _, changed = tracker.drain(now=200.0)
        self.assertIn(flow, changed)                      # final byte counts get saved

    def test_dns_answer_names_connection(self):
        tracker = self.run_sample()
        self.assertEqual(tracker.dns.get(GOOGLE), "www.google.com")

    def test_forged_dns_answer_ignored(self):
        """An answer nobody asked for (wrong id, or no query at all) must not relabel IPs."""
        tracker = Tracker(path_lookup=lambda pid: "")
        query = b.dns_query("bank.example", txid=1)
        forged = b.dns_response("bank.example", ["6.6.6.6"], txid=2)        # wrong id
        unsolicited = b.dns_response("apple.com", ["6.6.6.7"], txid=3)    # never asked
        stream = (b.shb() + b.idb(1, "en0") + b.pib(-1, "")
                  + b.epb(0, 1.0, b.ethernet(b.ipv4(ME, "1.1.1.1", 17, b.udp(5000, 53, query))), "out", 0)
                  + b.epb(0, 1.1, b.ethernet(b.ipv4("1.1.1.1", ME, 17, b.udp(53, 5000, forged))), "in", 0)
                  + b.epb(0, 1.2, b.ethernet(b.ipv4("1.1.1.1", ME, 17, b.udp(53, 5001, unsolicited))), "in", 0))
        for pkt in pcapng.PcapngStream().feed(stream):
            tracker.handle(pkt)
        self.assertEqual(tracker.dns, {})
        self.assertEqual(tracker.stats["dns_rejected"], 2)

    def test_scan_flood_is_rate_limited(self):
        tracker = Tracker(path_lookup=lambda pid: "")
        stream = b.shb() + b.idb(1, "en0")
        for i in range(500):                       # 500 probes from random ports in one second
            syn = b.tcp(10000 + i, 22, packets.SYN)
            stream += b.epb(0, 5.0 + i / 1000, b.ethernet(b.ipv4("10.9.9.9", ME, 6, syn)), "in")
        for pkt in pcapng.PcapngStream().feed(stream):
            tracker.handle(pkt)
        self.assertEqual(len(tracker.flows), tracker_mod.UNATTRIBUTED_IN_PER_SEC)
        self.assertEqual(tracker.stats["suppressed"], 500 - tracker_mod.UNATTRIBUTED_IN_PER_SEC)

    def test_flow_table_is_capped(self):
        tracker = Tracker(path_lookup=lambda pid: "")
        old_max = tracker_mod.MAX_FLOWS
        tracker_mod.MAX_FLOWS = 10
        try:
            stream = b.shb() + b.idb(1, "en0") + b.pib(9, "app")
            for i in range(25):
                syn = b.tcp(20000 + i, 443, packets.SYN)
                stream += b.epb(0, 1.0, b.ethernet(b.ipv4(ME, "8.8.8.8", 6, syn)), "out", 0)
            for pkt in pcapng.PcapngStream().feed(stream):
                tracker.handle(pkt)
            self.assertEqual(len(tracker.flows), 10)
            new, _ = tracker.drain(now=2.0)
            self.assertEqual(len(new), 25)          # every connection is still logged
        finally:
            tracker_mod.MAX_FLOWS = old_max

    def test_rdns_fills_unnamed(self):
        tracker = self.run_sample()
        spotify = [f for f in tracker.flows.values() if f.app == "Spotify"][0]
        self.assertIsNone(spotify.domain)
        tracker.apply_rdns("2600::1", "host.example.net")
        self.assertEqual((spotify.domain, spotify.domain_source), ("host.example.net", "rdns"))


class AppInfoTests(unittest.TestCase):
    def test_bundle_of(self):
        self.assertEqual(appinfo.bundle_of("/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper"),
                         "/Applications/Slack.app")
        self.assertEqual(appinfo.bundle_of("/usr/sbin/mDNSResponder"), "/usr/sbin/mDNSResponder")
        self.assertEqual(appinfo.display_name("/Applications/Slack.app", "Slack Helper"), "Slack")

    @unittest.skipUnless(sys.platform == "darwin", "macOS only")
    def test_pid_path_on_mac(self):
        path = appinfo.pid_path(os.getpid())
        self.assertTrue(path and os.path.exists(path), "pid_path returned %r" % path)

    @unittest.skipUnless(sys.platform == "darwin", "macOS only")
    def test_signature_of_system_tool(self):
        self.assertEqual(appinfo.check_signature("/usr/bin/curl")[0], "apple")

    def test_classify(self):
        dev = "Executable=/x\nAuthority=Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)\n" \
              "Authority=Developer ID Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=BQR82RBBHL\n"
        self.assertEqual(appinfo.classify_signature(dev, 0), ("developer", "Slack Technologies, Inc. (BQR82RBBHL)"))
        apple = "Authority=Software Signing\nAuthority=Apple Code Signing Certification Authority\n"
        self.assertEqual(appinfo.classify_signature(apple, 0)[0], "apple")
        store = "Authority=Apple Mac OS Application Signing\nTeamIdentifier=UBF8T346G9\n"
        self.assertEqual(appinfo.classify_signature(store, 0), ("appstore", "UBF8T346G9"))
        self.assertEqual(appinfo.classify_signature("Signature=adhoc\nTeamIdentifier=not set\n", 0)[0], "adhoc")
        self.assertEqual(appinfo.classify_signature("/x: code object is not signed at all\n", 1)[0], "unsigned")
        self.assertEqual(appinfo.classify_signature("/x: No such file\n", 1)[0], "unknown")


class SignatureTrustTests(unittest.TestCase):
    """The badge must depend on Apple vouching for the certificate, not its name."""

    def fake_codesign(self, describe, anchored_ok, intact_ok):
        def run(args, timeout):
            if args[0] == "-dv":
                return 0, describe
            if "-R" in args:
                return (0 if anchored_ok else 3), ""
            return (0 if intact_ok else 1), ""
        return run

    def check(self, describe, anchored_ok, intact_ok):
        real = appinfo._codesign
        appinfo._codesign = self.fake_codesign(describe, anchored_ok, intact_ok)
        try:
            return appinfo.check_signature(__file__)      # any existing path
        finally:
            appinfo._codesign = real

    DEV = "Authority=Developer ID Application: Totally Legit Inc (ABCDE12345)\n"

    def test_real_developer_id(self):
        self.assertEqual(self.check(self.DEV, True, True)[0], "developer")

    def test_homemade_certificate_with_borrowed_name(self):
        self.assertEqual(self.check(self.DEV, False, True)[0], "untrusted")

    def test_modified_after_signing(self):
        self.assertEqual(self.check(self.DEV, False, False)[0], "invalid")

    def test_fake_apple_name(self):
        self.assertEqual(self.check("Authority=Software Signing\n", False, True)[0], "untrusted")


class DataDirTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, "needs root")
    def test_symlink_inside_data_dir_is_not_followed(self):
        from snitchy.cli import prepare_data_dir
        tmp = tempfile.mkdtemp()
        victim = os.path.join(tmp, "victim")
        open(victim, "w").close()
        os.chmod(victim, 0o644)
        data = os.path.join(tmp, "data")
        os.mkdir(data)
        os.symlink(victim, os.path.join(data, "snitchy.db"))
        prepare_data_dir(data, "nobody")
        st = os.stat(victim)
        self.assertEqual((st.st_uid, st.st_mode & 0o777), (0, 0o644))      # untouched
        self.assertEqual(os.stat(data).st_mode & 0o777, 0o700)

    def test_symlinked_data_dir_refused(self):
        from snitchy.cli import prepare_data_dir
        tmp = tempfile.mkdtemp()
        os.symlink(tmp, tmp + "-link")
        with self.assertRaises(SystemExit):
            prepare_data_dir(tmp + "-link", "nobody")


class RootOwnershipTests(unittest.TestCase):
    """The service must refuse to run root code from anything a normal account could change."""

    def test_system_files_are_root_owned(self):
        self.assertTrue(service._root_owned_chain("/bin/sh"))

    @unittest.skipUnless(os.geteuid() == 0, "needs root to create files for another account")
    def test_user_owned_file_rejected(self):
        tmp = tempfile.mkdtemp(dir="/tmp")
        path = os.path.join(tmp, "python3")
        open(path, "w").close()
        os.chown(path, 65534, 65534)            # owned by "nobody"
        self.assertFalse(service._root_owned_chain(path))

    @unittest.skipUnless(os.geteuid() == 0, "needs root to create files for another account")
    def test_user_owned_folder_above_rejected(self):
        tmp = tempfile.mkdtemp(dir="/tmp")
        os.chown(tmp, 65534, 65534)             # someone else could swap what's inside
        path = os.path.join(tmp, "python3")
        open(path, "w").close()
        self.assertFalse(service._root_owned_chain(path))


class StartupTests(unittest.TestCase):
    def test_waits_for_busy_port(self):
        """Right after an update the old Snitchy may still hold the port briefly."""
        import socket
        from snitchy.cli import make_server_when_port_free
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        self.addCleanup(blocker.close)
        threading.Timer(1.0, blocker.close).start()            # old process exits after 1s
        store = Store(os.path.join(tempfile.mkdtemp(), "p.db"))
        server = make_server_when_port_free(
            lambda: make_server(store, Hub(), dict, port=port), port, timeout=10, interval=0.2)
        self.assertEqual(server.server_address[1], port)
        server.server_close()

    def test_gives_up_eventually(self):
        import socket
        from snitchy.cli import make_server_when_port_free
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        store = Store(os.path.join(tempfile.mkdtemp(), "q.db"))
        with self.assertRaises(OSError):
            make_server_when_port_free(lambda: make_server(store, Hub(), dict, port=port), port,
                                       timeout=0.5, interval=0.1)
        blocker.close()

    @unittest.skipUnless(os.geteuid() == 0, "needs root")
    def test_root_service_refuses_user_editable_code(self):
        from snitchy.cli import refuse_unsafe_root_run
        folder = tempfile.mkdtemp(dir="/tmp")
        os.chown(folder, 65534, 65534)
        with self.assertRaises(SystemExit):
            refuse_unsafe_root_run(folder)


class LauncherTests(unittest.TestCase):
    def test_launcher_runs_in_isolated_mode(self):
        """The file the service actually starts must work under `python3 -I`."""
        import subprocess
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        launcher = os.path.join(tempfile.mkdtemp(), "launch.py")
        with open(launcher, "w") as fh:
            fh.write(service.LAUNCHER_SOURCE % repo)
        out = subprocess.run([sys.executable, "-I", "-B", launcher, "--version"],
                             capture_output=True, text=True, cwd="/")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("snitchy", out.stdout)


class AuthTests(unittest.TestCase):
    """With a token, the log is only readable after signing in."""

    @classmethod
    def setUpClass(cls):
        store = Store(os.path.join(tempfile.mkdtemp(), "a.db"))
        cls.server = make_server(store, Hub(), lambda: {"capturing": True}, port=0, token="s3cret")
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def request(self, path, cookie=None):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path, headers={"Cookie": cookie} if cookie else {})
        res = conn.getresponse()
        res.read()
        return res

    def test_api_locked_without_cookie(self):
        self.assertEqual(self.request("/api/connections").status, 401)
        self.assertEqual(self.request("/api/connections", "snitchy_session=wrong").status, 401)

    def test_wrong_login_rejected(self):
        self.assertEqual(self.request("/login?token=nope").status, 403)

    def test_login_sets_strict_cookie_and_unlocks(self):
        res = self.request("/login?token=s3cret")
        self.assertEqual(res.status, 303)
        cookie = res.getheader("Set-Cookie")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertEqual(self.request("/api/connections", cookie.split(";")[0]).status, 200)

    def test_page_itself_loads_so_it_can_say_locked(self):
        self.assertEqual(self.request("/").status, 200)


class EndToEndTests(unittest.TestCase):
    """Feed the sample capture through the real engine, database and web server."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.store = Store(os.path.join(cls.tmp, "t.db"))
        cls.hub = Hub()
        cls.events = cls.hub.subscribe()
        engine = Engine(cls.store, cls.hub, resolve_ips=False)
        engine.feed_bytes(sample_stream())
        # Pretend the capture happened just now so time-range queries include it.
        for f in engine.tracker.flows.values():
            f.ts_start = f.ts_last = time.time() - 5
        engine.tick(force=True, now=time.time())
        cls.store.save_signature("/Applications/Evil.app", "unsigned", "")
        cls.server = make_server(cls.store, cls.hub, lambda: {"capturing": True}, port=0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def get(self, path, host=None):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path))
        if host:
            req.add_header("Host", host)
        with urllib.request.urlopen(req, timeout=5) as res:
            return res.status, res.read()

    def test_rows_stored_and_published(self):
        rows = self.store.query_connections()
        # The DNS answer, Safari and Spotify (loopback skipped)
        self.assertEqual(sorted(r["app"] for r in rows), ["Safari", "Spotify", "unknown"])
        published = []
        while not self.events.empty():
            published.append(self.events.get_nowait())
        self.assertEqual(sum(1 for e in published if e["type"] == "new"), 3)

    def test_api(self):
        status, body = self.get("/api/summary?range=1h")
        data = json.loads(body)
        self.assertEqual(data["totals"]["connections"], 3)
        self.assertEqual(data["top_domains"][0]["n"], 1)
        status, body = self.get("/api/connections?q=google")
        rows = json.loads(body)["rows"]
        self.assertEqual([r["app"] for r in rows], ["Safari"])
        status, body = self.get("/api/connections?app=Spotify")
        self.assertEqual(json.loads(body)["rows"][0]["via"], "nsurlsessiond")

    def test_dashboard_served(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Snitchy", body)

    def test_blocks_foreign_host_header(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get("/api/summary", host="evil.example.com")
        self.assertEqual(ctx.exception.code, 403)

    def test_blocks_path_traversal(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get("/../store.py")
        self.assertEqual(ctx.exception.code, 404)

    def test_prune(self):
        store = Store(os.path.join(self.tmp, "prune.db"))
        tracker = Tracker(path_lookup=lambda pid: "")
        for pkt in pcapng.PcapngStream().feed(sample_stream()):
            tracker.handle(pkt)
        new, _ = tracker.drain()
        store.insert_connections(new)                     # timestamps are from 2023
        self.assertEqual(store.prune(30), 3)
        self.assertEqual(store.prune(0), 0)               # 0 = keep forever


if __name__ == "__main__":
    unittest.main()
