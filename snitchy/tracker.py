"""Turns a stream of packets into a log of connections.

A "connection" (or flow) is one conversation between a local port and a
remote address: e.g. Safari's port 52341 talking to 17.253.144.10 port 443.
Hundreds of packets belong to one flow; the log gets one row per flow.

For each flow the tracker works out:

  * which app made it      - from Apple's per-packet process tags
  * where it went          - IP and port, plus the best hostname we can find:
      1. sni : the name the app put in its HTTPS "hello" (most accurate)
      2. dns : the name the app looked up to get that IP
      3. rdns: who owns the IP (looked up afterwards, a last resort)
  * who started it         - "out" (your Mac called out) or "in" (incoming)
  * how much data moved
"""

import time
from collections import OrderedDict
from dataclasses import dataclass, field

from . import appinfo, packets

TCP_IDLE = 15 * 60      # forget a quiet TCP connection after 15 min
TCP_CLOSED_GRACE = 10   # keep counting for 10s after FIN/RST (late packets)
UDP_IDLE = 2 * 60       # UDP has no "close", so time out after 2 min
SNI_MAX_PACKETS = 6     # give up looking for an HTTPS hostname after this
SNI_MAX_BYTES = 16384

# Changes to these fields are pushed to the dashboard quickly; byte counters
# are batched because they change on every packet.
BYTES_FLUSH_SECONDS = 5


@dataclass(eq=False)          # compare flows by identity, not by value
class Flow:
    key: tuple
    proto: str
    direction: str
    iface: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    ts_start: float
    ts_last: float
    app: str = "unknown"
    pid: int = None
    path: str = ""
    via: str = ""
    domain: str = None
    domain_source: str = None
    bytes_out: int = 0
    bytes_in: int = 0
    packets_out: int = 0
    packets_in: int = 0
    row_id: int = None
    # bookkeeping (not stored)
    closed_at: float = None
    fin_seen: set = field(default_factory=set)
    sni_buf: bytearray = field(default_factory=bytearray)
    sni_packets: int = 0
    sni_done: bool = False
    rdns_requested: bool = False
    dirty_meta: bool = False
    dirty_bytes: bool = False
    bytes_flushed_at: float = 0.0


class Tracker:
    def __init__(self, include_loopback=False, path_lookup=appinfo.pid_path, clock=time.time):
        self.include_loopback = include_loopback
        self._path_lookup = path_lookup
        self._clock = clock
        self.flows = {}                      # key -> Flow
        self.dns = OrderedDict()             # ip -> hostname (most recent lookups)
        self.dns_max = 100_000
        self._paths = OrderedDict()          # (pid, name) -> path on disk
        self._new = []
        self._finished = []
        self.stats = {"packets": 0, "decoded": 0, "flows": 0}

    # --- Feeding packets ------------------------------------------------------

    def handle(self, pkt):
        """Process one pcapng.Packet."""
        self.stats["packets"] += 1
        if not self.include_loopback and pkt.interface.name.startswith("lo"):
            return
        seg = packets.parse_segment(pkt.interface.linktype, pkt.data)
        if seg is None:
            return
        self.stats["decoded"] += 1

        if seg.proto == "udp" and seg.sport == 53 and seg.payload:
            self._learn_dns(seg.payload)

        outbound = self._is_outbound(pkt, seg)
        if outbound:
            local, remote = (seg.src, seg.sport), (seg.dst, seg.dport)
        else:
            local, remote = (seg.dst, seg.dport), (seg.src, seg.sport)
        key = (seg.proto, local, remote)

        flow = self.flows.get(key)
        if flow is not None and flow.closed_at is not None and seg.proto == "tcp" \
                and seg.flags & packets.SYN and not seg.flags & packets.ACK:
            # Same ports reused for a brand-new connection.
            self._finish(flow)
            flow = None
        if flow is None:
            flow = self._new_flow(key, pkt, seg, outbound, local, remote)

        flow.ts_last = pkt.timestamp
        if outbound:
            flow.bytes_out += pkt.orig_len
            flow.packets_out += 1
        else:
            flow.bytes_in += pkt.orig_len
            flow.packets_in += 1
        flow.dirty_bytes = True

        if flow.app == "unknown":
            self._attribute(flow, pkt)
        if seg.proto == "tcp":
            if seg.flags & packets.RST:
                flow.closed_at = flow.closed_at or pkt.timestamp
            elif seg.flags & packets.FIN:
                flow.fin_seen.add(outbound)
                if len(flow.fin_seen) == 2:
                    flow.closed_at = flow.closed_at or pkt.timestamp
            if outbound and seg.payload and not flow.sni_done:
                self._look_for_sni(flow, seg.payload)

    def _is_outbound(self, pkt, seg):
        if pkt.direction:
            return pkt.direction == "out"
        # No direction tag: guess that the side using the lower port is the server.
        return seg.dport < seg.sport

    def _new_flow(self, key, pkt, seg, outbound, local, remote):
        if seg.proto == "tcp" and seg.flags & packets.SYN and not seg.flags & packets.ACK:
            direction = "out" if outbound else "in"
        elif seg.proto == "tcp" and seg.flags & packets.SYN:
            direction = "in" if outbound else "out"     # SYN-ACK: the other side started it
        else:
            direction = "out" if outbound else "in"     # mid-stream / UDP: best guess
        flow = Flow(key=key, proto=seg.proto, direction=direction, iface=pkt.interface.name,
                    local_ip=local[0], local_port=local[1], remote_ip=remote[0], remote_port=remote[1],
                    ts_start=pkt.timestamp, ts_last=pkt.timestamp)
        name = self.dns.get(remote[0])
        if name:
            flow.domain, flow.domain_source = name, "dns"
        if seg.proto != "tcp":
            flow.sni_done = True
        self._attribute(flow, pkt)
        self.flows[key] = flow
        self._new.append(flow)
        self.stats["flows"] += 1
        return flow

    def _attribute(self, flow, pkt):
        """Credit the flow to an app using Apple's process tags."""
        proc = pkt.eprocess if pkt.eprocess and pkt.eprocess.pid > 0 else pkt.process
        if proc is None or proc.pid <= 0:
            return
        path = proc.path or self._path_for(proc)
        bundle = appinfo.bundle_of(path) if path else ""
        flow.pid = proc.pid
        flow.path = bundle
        flow.app = appinfo.display_name(bundle, proc.name) if bundle else (proc.name or "unknown")
        helper = pkt.process
        if helper is not None and helper is not proc and helper.pid > 0 and helper.pid != proc.pid:
            flow.via = helper.name
        flow.dirty_meta = True

    def _path_for(self, proc):
        key = (proc.pid, proc.name)
        path = self._paths.get(key)
        if path is None:
            path = self._path_lookup(proc.pid) or ""
            self._paths[key] = path
            if len(self._paths) > 20_000:
                self._paths.popitem(last=False)
        return path

    def _learn_dns(self, payload):
        answer = packets.parse_dns_answers(payload)
        if not answer:
            return
        name, addresses = answer
        for ip in addresses:
            self.dns[ip] = name
            self.dns.move_to_end(ip)
        while len(self.dns) > self.dns_max:
            self.dns.popitem(last=False)

    def _look_for_sni(self, flow, payload):
        flow.sni_buf += payload[:SNI_MAX_BYTES - len(flow.sni_buf)]
        flow.sni_packets += 1
        name = packets.parse_tls_sni(bytes(flow.sni_buf))
        if name:
            if (name, "sni") != (flow.domain, flow.domain_source):
                flow.domain, flow.domain_source = name, "sni"
                flow.dirty_meta = True
            flow.sni_done = True
        elif name == "" or flow.sni_packets >= SNI_MAX_PACKETS or len(flow.sni_buf) >= SNI_MAX_BYTES:
            flow.sni_done = True
        if flow.sni_done:
            flow.sni_buf = bytearray()

    # --- Late hostname from reverse DNS -----------------------------------------

    def apply_rdns(self, ip, name):
        for flow in self.flows.values():
            if flow.remote_ip == ip and not flow.domain:
                flow.domain, flow.domain_source = name, "rdns"
                flow.dirty_meta = True

    # --- Collecting results ------------------------------------------------------

    def expire(self, now=None):
        """Drop flows that have closed or gone quiet."""
        now = now if now is not None else self._clock()
        for flow in list(self.flows.values()):
            if flow.closed_at is not None:
                done = now - flow.closed_at > TCP_CLOSED_GRACE
            else:
                done = now - flow.ts_last > (TCP_IDLE if flow.proto == "tcp" else UDP_IDLE)
            if done:
                self._finish(flow)

    def _finish(self, flow):
        self.flows.pop(flow.key, None)
        self._finished.append(flow)

    def drain(self, now=None, force=False):
        """Return (new_flows, changed_flows) since the last call.

        new_flows need inserting into the log; changed_flows already have a
        row and need it updated. force=True includes every pending byte count.
        """
        now = now if now is not None else self._clock()
        new, self._new = self._new, []
        for f in new:
            f.dirty_meta = f.dirty_bytes = False
            f.bytes_flushed_at = now
        changed = []
        finished, self._finished = self._finished, []
        for f, final in [(f, False) for f in self.flows.values()] + [(f, True) for f in finished]:
            if f.row_id is None:
                continue                      # not in the log yet; its insert carries current values
            if f.dirty_meta or (f.dirty_bytes and (final or force or now - f.bytes_flushed_at >= BYTES_FLUSH_SECONDS)):
                changed.append(f)
                f.dirty_meta = f.dirty_bytes = False
                f.bytes_flushed_at = now
        return new, changed
