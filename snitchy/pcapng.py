"""Streaming reader for the pcapng format that macOS tcpdump writes.

How Snitchy gets per-app data
-----------------------------
macOS has a special capture interface called "pktap". When you run

    tcpdump -i pktap,all -P -U -w -

tcpdump writes a *pcapng* stream (the -P flag is Apple-specific) to stdout,
and Apple adds two non-standard things to it:

  * Process Information Blocks (PIB): one per process seen, carrying the
    process ID and name.
  * Options on each packet block pointing at the PIB of the process that
    sent/received the packet (and the "effective" process it was sent on
    behalf of, e.g. an app using a system helper).

Block type and option numbers below come from Apple's open-source libpcap
(libpcap/pcap/pcap-ng.h and pcap-darwin.c, apple-oss-distributions/libpcap).

This module only understands the file format. Turning packets into
"connections" is done in tracker.py.
"""

import struct
from dataclasses import dataclass, field

# --- Standard pcapng block types -------------------------------------------
BT_SHB = 0x0A0D0D0A        # Section Header Block (start of a stream)
BT_IDB = 0x00000001        # Interface Description Block
BT_EPB = 0x00000006        # Enhanced Packet Block (one captured packet)

# --- Apple-specific block type ---------------------------------------------
BT_PIB = 0x80000001        # Process Information Block

# --- Option codes ------------------------------------------------------------
OPT_ENDOFOPT = 0
IDB_NAME = 2               # interface name, e.g. "en0"
IDB_TSRESOL = 9            # timestamp resolution
EPB_FLAGS = 2              # bits 0-1: direction (1 = in, 2 = out)
EPB_PIB_INDEX = 0x8001     # which PIB (process) this packet belongs to
EPB_E_PIB_INDEX = 0x8003   # the "effective" process (who it was done for)
PIB_NAME = 2               # process name
PIB_PATH = 3               # process path (Apple does not currently write it)

BYTE_ORDER_MAGIC = 0x1A2B3C4D


@dataclass
class Interface:
    """One network interface (en0 = Wi-Fi/Ethernet, utun3 = VPN, ...)."""
    linktype: int
    name: str = ""
    ts_divisor: int = 1_000_000   # timestamp units per second


@dataclass
class Process:
    """A process as reported by the kernel at capture time."""
    pid: int
    name: str = ""
    path: str = ""


@dataclass
class Packet:
    """One captured packet plus the metadata Apple attached to it."""
    timestamp: float              # seconds since 1970
    interface: Interface
    data: bytes                   # starts at the link layer header
    orig_len: int                 # full on-the-wire length
    direction: str = ""           # "in", "out" or "" if unknown
    process: Process = None       # process owning the socket
    eprocess: Process = None      # effective process (on whose behalf)


@dataclass
class _Section:
    """State that resets every time a new Section Header Block appears."""
    endian: str = "<"
    interfaces: list = field(default_factory=list)
    processes: list = field(default_factory=list)


def _iter_options(buf, offset, end, endian):
    """Yield (code, value_bytes) for each option between offset and end."""
    while offset + 4 <= end:
        code, length = struct.unpack_from(endian + "HH", buf, offset)
        offset += 4
        if code == OPT_ENDOFOPT:
            return
        value = bytes(buf[offset:offset + length])
        offset += (length + 3) & ~3          # values are padded to 4 bytes
        yield code, value


def _text(value):
    return value.split(b"\0", 1)[0].decode("utf-8", "replace")


class PcapngStream:
    """Incremental pcapng parser.

    Feed it chunks of bytes as they arrive from tcpdump; it hands back the
    complete packets found so far and keeps any partial block for later.

        stream = PcapngStream()
        for packet in stream.feed(chunk):
            ...
    """

    def __init__(self):
        self._buf = bytearray()
        self._section = None

    def feed(self, chunk):
        self._buf += chunk
        packets = []
        offset = 0
        buf = self._buf
        while True:
            if len(buf) - offset < 12:
                break
            # The very first block tells us the byte order, so peek at it.
            if self._section is None or struct.unpack_from("<I", buf, offset)[0] == BT_SHB:
                if len(buf) - offset < 12:
                    break
                magic_le = struct.unpack_from("<I", buf, offset + 8)[0]
                if magic_le == BYTE_ORDER_MAGIC:
                    endian = "<"
                elif struct.unpack_from(">I", buf, offset + 8)[0] == BYTE_ORDER_MAGIC:
                    endian = ">"
                else:
                    raise ValueError("not a pcapng stream (bad section header)")
            else:
                endian = self._section.endian

            block_type, block_len = struct.unpack_from(endian + "II", buf, offset)
            if block_len < 12 or block_len % 4:
                raise ValueError("corrupt pcapng block length %d" % block_len)
            if len(buf) - offset < block_len:
                break                                    # wait for more bytes
            packet = self._handle_block(block_type, buf, offset, block_len, endian)
            if packet is not None:
                packets.append(packet)
            offset += block_len
        if offset:
            del self._buf[:offset]
        return packets

    # --- Block handlers ------------------------------------------------------

    def _handle_block(self, block_type, buf, start, length, endian):
        body = start + 8                  # skip type + length
        end = start + length - 4          # trailing length copy
        if block_type == BT_SHB:
            self._section = _Section(endian=endian)
            return None
        section = self._section
        if block_type == BT_IDB:
            linktype, _reserved, _snaplen = struct.unpack_from(endian + "HHI", buf, body)
            iface = Interface(linktype=linktype)
            for code, value in _iter_options(buf, body + 8, end, endian):
                if code == IDB_NAME:
                    iface.name = _text(value)
                elif code == IDB_TSRESOL and value:
                    r = value[0]
                    iface.ts_divisor = 2 ** (r & 0x7F) if r & 0x80 else 10 ** r
            section.interfaces.append(iface)
        elif block_type == BT_PIB:
            (pid,) = struct.unpack_from(endian + "I", buf, body)
            if pid >= 0x80000000:          # stored unsigned; -1 means unknown
                pid -= 0x100000000
            proc = Process(pid=pid)
            for code, value in _iter_options(buf, body + 4, end, endian):
                if code == PIB_NAME:
                    proc.name = _text(value)
                elif code == PIB_PATH:
                    proc.path = _text(value)
            section.processes.append(proc)
        elif block_type == BT_EPB:
            return self._packet(buf, body, end, endian)
        return None

    def _packet(self, buf, body, end, endian):
        section = self._section
        iface_id, ts_hi, ts_lo, caplen, orig_len = struct.unpack_from(endian + "IIIII", buf, body)
        if iface_id >= len(section.interfaces):
            return None
        iface = section.interfaces[iface_id]
        data_start = body + 20
        data = bytes(buf[data_start:data_start + caplen])
        packet = Packet(
            timestamp=((ts_hi << 32) | ts_lo) / iface.ts_divisor,
            interface=iface,
            data=data,
            orig_len=orig_len,
        )
        opts_start = data_start + ((caplen + 3) & ~3)
        for code, value in _iter_options(buf, opts_start, end, endian):
            if len(value) < 4:
                continue
            (number,) = struct.unpack(endian + "I", value[:4])
            if code == EPB_FLAGS:
                packet.direction = {1: "in", 2: "out"}.get(number & 3, "")
            elif code == EPB_PIB_INDEX and number < len(section.processes):
                packet.process = section.processes[number]
            elif code == EPB_E_PIB_INDEX and number < len(section.processes):
                packet.eprocess = section.processes[number]
        return packet
