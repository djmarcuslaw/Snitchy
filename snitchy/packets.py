"""Decoding raw packet bytes: link layer -> IP -> TCP/UDP, plus DNS and TLS.

Everything here is a pure function on bytes, so it is easy to unit test.
Malformed or unsupported packets simply return None; on a live network
there is always some odd traffic and Snitchy should skip it, not crash.
"""

import ipaddress
import struct
from dataclasses import dataclass

# Link-layer types we may see from pktap (Apple uses DLT numbers here).
LINK_NULL = 0          # loopback / utun: 4-byte address family header
LINK_ETHERNET = 1      # Wi-Fi and Ethernet both look like Ethernet
LINK_RAW = (12, 101)   # bare IP packet (DLT_RAW / LINKTYPE_RAW)
LINK_IPV4 = 228
LINK_IPV6 = 229

AF_INET = 2
AF_INET6 = (24, 28, 30)   # BSD variants; macOS uses 30

PROTO_TCP = 6
PROTO_UDP = 17

# TCP flag bits
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


@dataclass
class Segment:
    """The parts of a TCP/UDP packet Snitchy cares about."""
    proto: str            # "tcp" or "udp"
    src: str
    sport: int
    dst: str
    dport: int
    flags: int            # TCP flags (0 for UDP)
    payload: bytes


def ip_payload(linktype, data):
    """Strip the link-layer header and return the IP packet, or None."""
    if linktype == LINK_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack_from("!H", data, 12)[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8) and len(data) >= offset + 4:   # VLAN tags
            ethertype = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
        return data[offset:] if ethertype in (0x0800, 0x86DD) else None
    if linktype == LINK_NULL:
        if len(data) < 4:
            return None
        family = struct.unpack_from("<I", data, 0)[0]   # host byte order
        if family not in (AF_INET,) + AF_INET6:
            family = struct.unpack_from(">I", data, 0)[0]
        return data[4:] if family in (AF_INET,) + AF_INET6 else None
    if linktype in LINK_RAW or linktype in (LINK_IPV4, LINK_IPV6):
        return data
    return None


def parse_segment(linktype, data):
    """Decode a captured frame into a Segment (TCP/UDP only), or None."""
    ip = ip_payload(linktype, data)
    if not ip:
        return None
    version = ip[0] >> 4
    if version == 4:
        if len(ip) < 20:
            return None
        ihl = (ip[0] & 0x0F) * 4
        frag = struct.unpack_from("!H", ip, 6)[0]
        if frag & 0x1FFF:          # a later fragment has no TCP/UDP header
            return None
        proto = ip[9]
        src = str(ipaddress.IPv4Address(ip[12:16]))
        dst = str(ipaddress.IPv4Address(ip[16:20]))
        total = struct.unpack_from("!H", ip, 2)[0]
        l4 = ip[ihl:total] if total >= ihl else ip[ihl:]
    elif version == 6:
        if len(ip) < 40:
            return None
        proto = ip[6]
        src = str(ipaddress.IPv6Address(ip[8:24]))
        dst = str(ipaddress.IPv6Address(ip[24:40]))
        l4 = ip[40:]
        # Walk common extension headers (hop-by-hop, routing, dest options).
        while proto in (0, 43, 60) and len(l4) >= 8:
            proto, hdr_len = l4[0], (l4[1] + 1) * 8
            l4 = l4[hdr_len:]
    else:
        return None

    if proto == PROTO_TCP and len(l4) >= 20:
        sport, dport = struct.unpack_from("!HH", l4, 0)
        data_offset = (l4[12] >> 4) * 4
        return Segment("tcp", src, sport, dst, dport, l4[13], bytes(l4[data_offset:]))
    if proto == PROTO_UDP and len(l4) >= 8:
        sport, dport = struct.unpack_from("!HH", l4, 0)
        return Segment("udp", src, sport, dst, dport, 0, bytes(l4[8:]))
    return None


# --- DNS ---------------------------------------------------------------------

def _read_name(msg, offset, depth=0):
    """Read a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels = []
    jumped_to = None
    while True:
        if offset >= len(msg) or depth > 20:
            raise ValueError("bad dns name")
        length = msg[offset]
        if length & 0xC0 == 0xC0:                       # compression pointer
            if offset + 1 >= len(msg):
                raise ValueError("bad dns pointer")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if jumped_to is None:
                jumped_to = offset + 2
            offset = pointer
            depth += 1
            continue
        offset += 1
        if length == 0:
            break
        labels.append(msg[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels).lower(), (jumped_to if jumped_to is not None else offset)


def parse_dns_answers(msg):
    """Return (question_name, [ip, ...]) for a DNS response, or None.

    CNAME chains are followed implicitly: every A/AAAA address in the answer
    is credited to the name the app originally asked for, which is what a
    person reading the log wants to see.
    """
    try:
        if len(msg) < 12:
            return None
        flags, qdcount, ancount = struct.unpack_from("!HHH", msg, 2)
        if not flags & 0x8000 or qdcount < 1:           # not a response
            return None
        offset = 12
        question, offset = _read_name(msg, offset)
        offset += 4                                       # qtype + qclass
        for _ in range(qdcount - 1):                      # rare, but skip extras
            _, offset = _read_name(msg, offset)
            offset += 4
        addresses = []
        for _ in range(ancount):
            _, offset = _read_name(msg, offset)
            rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", msg, offset)
            offset += 10
            rdata = msg[offset:offset + rdlen]
            offset += rdlen
            if rtype == 1 and rdlen == 4:
                addresses.append(str(ipaddress.IPv4Address(rdata)))
            elif rtype == 28 and rdlen == 16:
                addresses.append(str(ipaddress.IPv6Address(rdata)))
        return question, addresses
    except (ValueError, struct.error, IndexError):
        return None


# --- TLS (HTTPS) ---------------------------------------------------------------

def parse_tls_sni(data):
    """Extract the server name from a TLS ClientHello, if present.

    Returns:
      * the hostname (str) if found,
      * "" if this is definitely not a ClientHello or has no SNI,
      * None if the ClientHello looks truncated (wait for more bytes).
    """
    if len(data) < 5:
        return None if data[:1] in (b"", b"\x16") else ""
    if data[0] != 0x16 or data[1] != 0x03:            # handshake record, TLS 3.x
        return ""
    record_len = struct.unpack_from("!H", data, 3)[0]
    if len(data) < 9:
        return None
    if data[5] != 0x01:                               # ClientHello
        return ""
    hello_len = int.from_bytes(data[6:9], "big")
    # A big ClientHello can span several TLS records; join their bodies.
    body = bytearray()
    offset = 0
    while offset + 5 <= len(data) and data[offset] == 0x16:
        rlen = struct.unpack_from("!H", data, offset + 3)[0]
        body += data[offset + 5:offset + 5 + rlen]
        offset += 5 + rlen
        if len(body) >= hello_len + 4:
            break
    if len(body) < hello_len + 4:
        return None if record_len else ""
    try:
        p = 4 + 2 + 32                                # header, version, random
        p += 1 + body[p]                              # session id
        p += 2 + struct.unpack_from("!H", body, p)[0]  # cipher suites
        p += 1 + body[p]                              # compression methods
        if p + 2 > len(body):
            return ""
        ext_end = p + 2 + struct.unpack_from("!H", body, p)[0]
        p += 2
        while p + 4 <= ext_end:
            ext_type, ext_len = struct.unpack_from("!HH", body, p)
            p += 4
            if ext_type == 0:                         # server_name
                q = p + 2
                while q + 3 <= p + ext_len:
                    name_type, name_len = body[q], struct.unpack_from("!H", body, q + 1)[0]
                    if name_type == 0:
                        return body[q + 3:q + 3 + name_len].decode("ascii", "replace").lower()
                    q += 3 + name_len
                return ""
            p += ext_len
    except (struct.error, IndexError):
        return ""
    return ""
