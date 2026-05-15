"""
packet.py — Custom TCP-like packet over UDP.

Header layout (15 bytes):
  ┌────────┬──────────┬──────────┬──────────────┬──────────┐
  │ flags  │  seq_num │  ack_num │   checksum   │ data_len │
  │ 1 byte │  4 bytes │  4 bytes │   2 bytes    │  4 bytes │
  └────────┴──────────┴──────────┴──────────────┴──────────┘
  Total: 15 bytes

Flags (bitmask):
  SYN    = 0x01  – synchronise (start of handshake)
  SYNACK = 0x02  – synchronise-acknowledge
  ACK    = 0x04  – acknowledge
  FIN    = 0x08  – finish (teardown)
  PSH    = 0x10  – push (last data segment in a send() call)
"""

import struct

# ── Header ────────────────────────────────────────────────────────────────────
HEADER_FORMAT = '!BIIHI'          # big-endian: B I I H I
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 1+4+4+2+4 = 15 bytes

# ── Flags ─────────────────────────────────────────────────────────────────────
SYN    = 0x01
SYNACK = 0x02
ACK    = 0x04
FIN    = 0x08
PSH    = 0x10   # push / last-segment marker


class Packet:
    """
    A single RDT packet with a fixed-size header followed by variable data.

    Attributes:
        flags   – bitmask of SYN / SYNACK / ACK / FIN / PSH
        seq_num – sender's sequence number (byte offset)
        ack_num – cumulative acknowledgement number
        data    – payload bytes
    """

    __slots__ = ('flags', 'seq_num', 'ack_num', 'data', '_stored_cs')

    def __init__(self, flags: int = 0, seq_num: int = 0,
                 ack_num: int = 0, data: bytes = b''):
        self.flags    = flags
        self.seq_num  = seq_num
        self.ack_num  = ack_num
        self.data     = data if isinstance(data, bytes) else data.encode()
        self._stored_cs: int | None = None   # filled by unpack()

    # ── Checksum (Internet / RFC 1071 16-bit ones-complement sum) ─────────────

    @staticmethod
    def _ones_complement_sum(raw: bytes) -> int:
        if len(raw) % 2:
            raw += b'\x00'
        s = 0
        for i in range(0, len(raw), 2):
            s += (raw[i] << 8) | raw[i + 1]
            s  = (s & 0xFFFF) + (s >> 16)   # fold carry
        return (~s) & 0xFFFF

    def compute_checksum(self) -> int:
        """Compute checksum over header (with checksum field zeroed) + data."""
        pseudo_hdr = struct.pack(HEADER_FORMAT,
                                 self.flags, self.seq_num, self.ack_num,
                                 0,          len(self.data))
        return self._ones_complement_sum(pseudo_hdr + self.data)

    # ── Serialisation ─────────────────────────────────────────────────────────

    def pack(self) -> bytes:
        """Serialise packet → bytes (computes checksum automatically)."""
        cs  = self.compute_checksum()
        hdr = struct.pack(HEADER_FORMAT,
                          self.flags, self.seq_num, self.ack_num,
                          cs,         len(self.data))
        return hdr + self.data

    @classmethod
    def unpack(cls, raw: bytes) -> 'Packet | None':
        """Deserialise bytes → Packet.  Returns None if too short."""
        if len(raw) < HEADER_SIZE:
            return None
        flags, seq, ack, stored_cs, dlen = struct.unpack(
            HEADER_FORMAT, raw[:HEADER_SIZE])
        data = raw[HEADER_SIZE: HEADER_SIZE + dlen]
        p = cls(flags, seq, ack, data)
        p._stored_cs = stored_cs
        return p

    def verify_checksum(self) -> bool:
        """Return True iff the stored checksum matches the computed one."""
        return self._stored_cs == self.compute_checksum()

    # ── Flag helpers ──────────────────────────────────────────────────────────

    def is_syn(self)    -> bool: return bool(self.flags & SYN)
    def is_synack(self) -> bool: return bool(self.flags & SYNACK)
    def is_ack(self)    -> bool: return bool(self.flags & ACK)
    def is_fin(self)    -> bool: return bool(self.flags & FIN)
    def is_psh(self)    -> bool: return bool(self.flags & PSH)

    # ── Repr ──────────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        names: list[str] = []
        if self.is_syn():    names.append('SYN')
        if self.is_synack(): names.append('SYNACK')
        if self.is_ack():    names.append('ACK')
        if self.is_fin():    names.append('FIN')
        if self.is_psh():    names.append('PSH')
        flags_str = '|'.join(names) or 'NONE'
        return (f'Packet(flags={flags_str}, seq={self.seq_num}, '
                f'ack={self.ack_num}, len={len(self.data)}, '
                f'cs={self._stored_cs or self.compute_checksum():#06x})')
