"""Helpers that build fake packets and pcapng streams for the tests.

They write exactly the byte layout macOS tcpdump produces (see
snitchy/pcapng.py), so the parser can be tested without a Mac.
"""

import ipaddress
import struct

from snitchy import pcapng


def _opt(code, value, endian="<"):
    pad = (-len(value)) % 4
    return struct.pack(endian + "HH", code, len(value)) + value + b"\0" * pad


def _end(endian="<"):
    return struct.pack(endian + "HH", 0, 0)


def block(block_type, body, endian="<"):
    pad = (-len(body)) % 4
    body = body + b"\0" * pad
    length = 12 + len(body)
    return struct.pack(endian + "II", block_type, length) + body + struct.pack(endian + "I", length)


def shb(endian="<"):
    body = struct.pack(endian + "IHHq", pcapng.BYTE_ORDER_MAGIC, 1, 0, -1)
    return block(pcapng.BT_SHB, body, endian)


def idb(linktype, name, endian="<"):
    body = struct.pack(endian + "HHI", linktype, 0, 2048)
    body += _opt(pcapng.IDB_NAME, name.encode(), endian) + _end(endian)
    return block(pcapng.BT_IDB, body, endian)


def pib(pid, name, endian="<"):
    body = struct.pack(endian + "I", pid & 0xFFFFFFFF)
    body += _opt(pcapng.PIB_NAME, name.encode() + b"\0", endian) + _end(endian)
    return block(pcapng.BT_PIB, body, endian)


def epb(iface, ts, data, direction=None, pib_index=None, e_pib_index=None, orig_len=None, endian="<"):
    micros = int(ts * 1_000_000)
    body = struct.pack(endian + "IIIII", iface, micros >> 32, micros & 0xFFFFFFFF, len(data),
                       orig_len or len(data))
    body += data + b"\0" * ((-len(data)) % 4)
    opts = b""
    if direction:
        opts += _opt(pcapng.EPB_FLAGS, struct.pack(endian + "I", {"in": 1, "out": 2}[direction]), endian)
    if pib_index is not None:
        opts += _opt(pcapng.EPB_PIB_INDEX, struct.pack(endian + "I", pib_index), endian)
    if e_pib_index is not None:
        opts += _opt(pcapng.EPB_E_PIB_INDEX, struct.pack(endian + "I", e_pib_index), endian)
    if opts:
        body += opts + _end(endian)
    return block(pcapng.BT_EPB, body, endian)


# --- Packets ---------------------------------------------------------------

def ethernet(ip_packet, v6=False):
    return b"\x11" * 6 + b"\x22" * 6 + struct.pack("!H", 0x86DD if v6 else 0x0800) + ip_packet


def null_link(ip_packet, v6=False):
    return struct.pack("<I", 30 if v6 else 2) + ip_packet


def ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header + payload


def ipv6(src, dst, proto, payload):
    header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), proto, 64,
                         ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed)
    return header + payload


def tcp(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_query(question, txid=0x1234):
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + _dns_name(question) + struct.pack("!HH", 1, 1)


def dns_response(question, answers, cname=None, txid=0x1234):
    """answers: list of IP strings. With cname, answer chain is question -> cname -> IPs."""
    records = []
    if cname:
        target = _dns_name(cname)
        records.append(b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(target)) + target)
        owner = b"\xc0" + bytes([12 + len(_dns_name(question)) + 4 + 12])   # pointer to cname rdata
    else:
        owner = b"\xc0\x0c"                                                  # pointer to question
    for ip in answers:
        addr = ipaddress.ip_address(ip)
        rtype = 28 if addr.version == 6 else 1
        records.append(owner + struct.pack("!HHIH", rtype, 1, 60, len(addr.packed)) + addr.packed)
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, len(records), 0, 0)
    return header + _dns_name(question) + struct.pack("!HH", 1, 1) + b"".join(records)


def client_hello(server_name, padding=0):
    """A minimal but well-formed TLS 1.2/1.3 ClientHello with an SNI extension."""
    name = server_name.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack("!HH", 0x0015, padding) + b"\0" * padding if padding else b""
    extensions += struct.pack("!HH", 0, len(sni)) + sni
    body = (b"\x03\x03" + b"\x42" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
