"""
rdt_socket.py — Reliable Data Transfer Socket.

Simulates TCP semantics over a raw UDP socket:

  ┌─────────────────────────────────────────────────────┐
  │  Three-way handshake  (SYN → SYNACK → ACK)          │
  │  Stop-and-Wait  data transfer  (RFC 1122 §3.4.1)    │
  │  Sequence numbers  &  cumulative ACKs                │
  │  Checksum  error detection  (RFC 1071)               │
  │  Retransmission on timeout                           │
  │  Duplicate-packet detection  &  re-ACK              │
  │  Connection teardown  (FIN → ACK)                   │
  │  Packet-loss simulation                              │
  │  Packet-corruption simulation                        │
  └─────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
import random
import socket
import time

from packet import (
    HEADER_SIZE, ACK, FIN, PSH, SYN, SYNACK, Packet
)

log = logging.getLogger(__name__)

# ── Tunable constants ─────────────────────────────────────────────────────────
TIMEOUT   = 2.0     # retransmission timeout (seconds)
MAX_RETRY = 15      # give up after this many consecutive failures
BUF       = 65535   # UDP receive buffer size
MSS       = 1400    # Maximum Segment Size (bytes of data per packet)
RECV_WAIT = 30.0    # total time recv() will wait for a stream to begin


class RDTSocket:
    """
    Reliable Data Transfer socket.

    Usage (client)::
        sock = RDTSocket()
        sock.connect(('127.0.0.1', 8080))
        sock.send(b'hello')
        data = sock.recv()
        sock.close()

    Usage (server)::
        srv = RDTSocket()
        srv.bind(('0.0.0.0', 8080))
        conn, addr = srv.accept()   # blocks until client connects
        data = conn.recv()
        conn.send(b'world')
        conn.close()
    """

    def __init__(self, loss_prob: float = 0.0, corrupt_prob: float = 0.0):
        self._udp         = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.settimeout(TIMEOUT)
        self._peer: tuple | None = None   # (host, port) of connected peer
        self._seq         = 0             # next byte index to send
        self._ack         = 0             # next byte index expected from peer
        self._connected   = False
        self.loss_prob    = loss_prob     # P(outgoing packet is silently dropped)
        self.corrupt_prob = corrupt_prob  # P(outgoing packet is bit-flipped)

    # ── Socket management ─────────────────────────────────────────────────────

    def bind(self, addr: tuple):
        self._udp.bind(addr)
        log.info(f'Bound to {addr}')

    def getsockname(self) -> tuple:
        return self._udp.getsockname()

    # ── Simulation helpers ────────────────────────────────────────────────────

    def simulate_loss(self, prob: float):
        """Set outgoing packet-loss probability (0.0 – 1.0)."""
        self.loss_prob = max(0.0, min(1.0, prob))
        log.info(f'[SIM] Loss probability set to {self.loss_prob:.0%}')

    def simulate_corruption(self, prob: float):
        """Set outgoing packet-corruption probability (0.0 – 1.0)."""
        self.corrupt_prob = max(0.0, min(1.0, prob))
        log.info(f'[SIM] Corruption probability set to {self.corrupt_prob:.0%}')

    def _corrupt_bytes(self, raw: bytes) -> bytes:
        """Flip a random bit somewhere in the packet to simulate corruption."""
        ba  = bytearray(raw)
        idx = random.randint(0, len(ba) - 1)
        ba[idx] ^= random.randint(1, 0xFF)
        return bytes(ba)

    # ── Low-level TX / RX ─────────────────────────────────────────────────────

    def _tx(self, pkt: Packet, dest: tuple | None = None):
        """
        Transmit *pkt* to *dest* (or self._peer).
        Applies loss/corruption simulation before sending.
        """
        addr = dest or self._peer
        if addr is None:
            raise RuntimeError('No destination address; call connect() first')
        raw = pkt.pack()

        if random.random() < self.loss_prob:
            log.warning(f'[SIM] LOST     → {addr}  {pkt}')
            return                          # silently drop

        if random.random() < self.corrupt_prob:
            raw = self._corrupt_bytes(raw)
            log.warning(f'[SIM] CORRUPT  → {addr}  {pkt}')

        self._udp.sendto(raw, addr)
        log.debug(f'TX → {addr}  {pkt}')

    def _rx(self, deadline: float) -> tuple[Packet | None, tuple | None]:
        """
        Wait for a packet until *deadline* (Unix timestamp).
        Filters packets by self._peer if it is set.
        Returns (Packet, src_addr) or (None, None) on timeout.
        """
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return None, None
            self._udp.settimeout(remaining)
            try:
                raw, addr = self._udp.recvfrom(BUF)
            except socket.timeout:
                return None, None

            # Address filtering: ignore packets not from our peer
            if self._peer and addr != self._peer:
                log.debug(f'RX ignored from unexpected addr {addr}')
                continue

            pkt = Packet.unpack(raw)
            if pkt is None:
                continue

            log.debug(f'RX ← {addr}  {pkt}')
            return pkt, addr

    def _send_ack(self, ack_num: int, dest: tuple | None = None):
        """Send a bare ACK (no data)."""
        a = Packet(flags=ACK, seq_num=self._seq, ack_num=ack_num)
        target = dest or self._peer
        self._udp.sendto(a.pack(), target)   # direct send — no simulation
        log.debug(f'ACK → {target}  ack_num={ack_num}')

    # ── Three-way handshake ───────────────────────────────────────────────────

    def connect(self, addr: tuple):
        """
        Client side: perform three-way handshake with the server at *addr*.

        Flow:
          Client ──SYN(seq=x)──────────────→ Server
          Client ←──SYNACK(seq=y, ack=x+1)── Server
          Client ──ACK(ack=y+1)────────────→ Server
        """
        self._peer = addr
        self._seq  = random.randint(0, 2**31 - 1)
        client_isn = self._seq

        syn = Packet(flags=SYN, seq_num=client_isn)
        for attempt in range(1, MAX_RETRY + 1):
            log.info(f'[HS] Sending SYN seq={client_isn}  attempt {attempt}/{MAX_RETRY}')
            self._tx(syn)

            pkt, _ = self._rx(time.time() + TIMEOUT)
            if pkt is None:
                log.warning('[HS] Timeout waiting for SYNACK — retrying')
                continue
            if not pkt.verify_checksum():
                log.warning('[HS] Received corrupted SYNACK — retrying')
                continue
            if pkt.is_synack() and pkt.ack_num == client_isn + 1:
                log.info(f'[HS] SYNACK received  server_seq={pkt.seq_num}')
                self._ack = pkt.seq_num + 1   # expect server_isn + 1
                self._seq = client_isn + 1    # SYN consumes one seq number
                ack = Packet(flags=ACK, seq_num=self._seq, ack_num=self._ack)
                self._tx(ack)
                self._connected = True
                log.info('[HS] ✓ Connection established (client)')
                return

        raise ConnectionError(f'connect() failed after {MAX_RETRY} retries')

    def accept(self) -> tuple['RDTSocket', tuple]:
        """
        Server side: block until a client initiates a connection.
        Returns (child_socket, client_addr).

        Flow:
          Server ←──SYN(seq=x)──────────────── Client
          Server ──SYNACK(seq=y, ack=x+1)────→ Client
          Server ←──ACK(ack=y+1)──────────── Client
        """
        log.info('Waiting for incoming SYN …')

        # ── Step 1: wait for SYN ──────────────────────────────────────────────
        while True:
            pkt, client_addr = self._rx(time.time() + 3600)  # wait up to 1 hour
            if pkt is None:
                continue
            if not pkt.verify_checksum():
                log.warning('[HS] Corrupted SYN — ignoring')
                continue
            if pkt.is_syn():
                log.info(f'[HS] SYN from {client_addr}  seq={pkt.seq_num}')
                break

        client_isn = pkt.seq_num
        server_isn = random.randint(0, 2**31 - 1)

        # ── Step 2: send SYNACK, wait for ACK ─────────────────────────────────
        synack = Packet(flags=SYNACK,
                        seq_num=server_isn,
                        ack_num=client_isn + 1)

        for attempt in range(1, MAX_RETRY + 1):
            log.info(f'[HS] Sending SYNACK  seq={server_isn}  attempt {attempt}/{MAX_RETRY}')
            self._udp.sendto(synack.pack(), client_addr)   # bypass simulation

            pkt, addr = self._rx(time.time() + TIMEOUT)
            if pkt is None:
                log.warning('[HS] Timeout waiting for ACK — retrying SYNACK')
                continue
            if addr != client_addr:
                continue
            if not pkt.verify_checksum():
                log.warning('[HS] Corrupted ACK — retrying SYNACK')
                continue
            if pkt.is_ack() and pkt.ack_num == server_isn + 1:
                log.info(f'[HS] ✓ ACK received — connection established with {client_addr}')

                # Create a child socket that shares the underlying UDP socket
                child              = RDTSocket(self.loss_prob, self.corrupt_prob)
                child._udp         = self._udp        # shared socket
                child._peer        = client_addr
                child._seq         = server_isn + 1   # SYNACK consumed one seq
                child._ack         = client_isn + 1
                child._connected   = True
                return child, client_addr

        raise ConnectionError('accept() handshake failed after max retries')

    # ── Data Transfer — Stop-and-Wait ─────────────────────────────────────────

    def send(self, data: bytes | str):
        """
        Reliably send *data* to the peer.

        Data is fragmented into MSS-sized segments.  Each segment is sent and
        its ACK waited for before the next segment is sent (stop-and-wait).
        The last segment is marked with the PSH flag so the receiver knows
        where the message ends.
        """
        if isinstance(data, str):
            data = data.encode()

        total  = len(data)
        offset = 0
        log.info(f'send() starting: {total} bytes total')

        # Always send at least one packet so the receiver's PSH detection fires.
        # An empty payload with PSH signals an empty message end-of-stream.
        if total == 0:
            self._send_segment(b'', ACK | PSH)
        else:
            while offset < total:
                chunk   = data[offset: offset + MSS]
                is_last = (offset + len(chunk)) >= total
                flags   = ACK | (PSH if is_last else 0)
                self._send_segment(chunk, flags)
                offset += len(chunk)

        log.info(f'send() complete: {total} bytes sent')

    def _send_segment(self, data: bytes, flags: int):
        """
        Send one segment and wait for the cumulative ACK (stop-and-wait).
        Retransmits on timeout or checksum failure.
        """
        pkt          = Packet(flags=flags,
                              seq_num=self._seq,
                              ack_num=self._ack,
                              data=data)
        expected_ack = self._seq + len(data)

        for attempt in range(1, MAX_RETRY + 1):
            log.info(f'TX segment  seq={self._seq}  len={len(data)}  '
                     f'attempt {attempt}/{MAX_RETRY}')
            self._tx(pkt)

            ack_pkt, _ = self._rx(time.time() + TIMEOUT)
            if ack_pkt is None:
                log.warning(f'Timeout: no ACK for seq={self._seq} — retransmitting')
                continue
            if not ack_pkt.verify_checksum():
                log.warning('Received corrupted ACK — retransmitting')
                continue
            if ack_pkt.is_ack() and ack_pkt.ack_num == expected_ack:
                log.info(f'ACK received: ack_num={expected_ack} ✓')
                self._seq = expected_ack
                return
            if ack_pkt.is_fin():
                # Peer closed while we were still sending data.
                # ACK their FIN cleanly, then abort this send.
                log.warning('Peer sent FIN during active data transfer '
                            '— ACKing FIN and aborting send')
                self._send_ack(ack_pkt.seq_num + 1)
                self._connected = False
                raise ConnectionResetError(
                    'Connection reset by peer (FIN received mid-send)')
            log.warning(f'Unexpected ACK ack_num={ack_pkt.ack_num} '
                        f'(expected {expected_ack}) — retransmitting')

        raise OSError(f'_send_segment failed after {MAX_RETRY} attempts '
                      f'(seq={self._seq})')

    def recv(self) -> bytes:
        """
        Receive a complete message from the peer.

        Collects segments until the PSH flag or a FIN is received.
        Handles duplicate packets (re-ACKs without duplicating data) and
        drops packets with invalid checksums (sender will time out and retransmit).

        Returns the reassembled data bytes.
        """
        chunks:              list[bytes] = []
        consecutive_timeouts             = 0
        deadline                         = time.time() + RECV_WAIT

        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError('recv() hard deadline exceeded — PSH/FIN never arrived')

            pkt, addr = self._rx(time.time() + min(remaining, TIMEOUT))

            # ── Timeout on this _rx() call ────────────────────────────────────
            # One timeout does NOT mean end-of-stream. The sender may be
            # retransmitting a lost segment right now. Only give up after
            # MAX_RETRY *consecutive* timeouts (peer is truly dead).
            if pkt is None:
                consecutive_timeouts += 1
                log.debug(
                    f'recv() _rx timeout #{consecutive_timeouts}/{MAX_RETRY}'
                    f' — peer may be retransmitting, waiting …'
                )
                if consecutive_timeouts >= MAX_RETRY:
                    raise TimeoutError(
                        f'recv() gave up after {MAX_RETRY} consecutive timeouts'
                    )
                continue

            consecutive_timeouts = 0   # any successful packet resets the counter


            # ── FIN: peer closed sending side ────────────────────────────────
            if pkt.is_fin():
                log.info(f'FIN received from {addr}  seq={pkt.seq_num}')
                self._send_ack(pkt.seq_num + 1, addr)
                self._connected = False
                break

            # ── Checksum error: drop and wait for retransmission ─────────────
            if not pkt.verify_checksum():
                log.warning(f'Checksum FAILED for seq={pkt.seq_num} — packet dropped '
                            f'(sender will retransmit on timeout)')
                continue  # do NOT send ACK; let sender's timer fire

            # ── Duplicate detection: seq_num already acknowledged ─────────────
            if pkt.seq_num < self._ack:
                log.warning(f'Duplicate segment seq={pkt.seq_num} '
                            f'(already at ack={self._ack}) — re-ACKing')
                self._send_ack(self._ack, addr)
                continue

            # ── In-order segment ─────────────────────────────────────────────
            if pkt.seq_num == self._ack:
                log.info(f'RX segment  seq={pkt.seq_num}  len={len(pkt.data)}')
                if pkt.data:
                    chunks.append(pkt.data)
                self._ack += len(pkt.data)
                self._send_ack(self._ack, addr)

                if pkt.is_psh():
                    log.info('PSH received — end of stream ✓')
                    break
            else:
                # Out-of-order (should not occur with stop-and-wait)
                log.warning(f'Out-of-order seq={pkt.seq_num} '
                            f'expected={self._ack} — ignoring')

        return b''.join(chunks)

    # ── Connection teardown ───────────────────────────────────────────────────

    def close(self):
        """
        Send a FIN to the peer and wait for an ACK.

        Handles two teardown scenarios:

        Normal (one side initiates):
          Us  ──FIN──→  Peer
          Us  ←──ACK──  Peer

        Simultaneous close (both sides call close() at the same time,
        which always happens in HTTP/1.0 because the server closes right
        after send() and the client closes right after recv()):
          Us  ──FIN──→  Peer
          Us  ←──FIN──  Peer   (crosses in the network)
          Us  ──ACK──→  Peer   (we ACK their FIN and consider ourselves done)
        """
        if not self._connected or self._peer is None:
            return

        fin = Packet(flags=FIN, seq_num=self._seq, ack_num=self._ack)
        for attempt in range(1, MAX_RETRY + 1):
            log.info(f'Sending FIN  attempt {attempt}/{MAX_RETRY}')
            self._tx(fin)
            pkt, _ = self._rx(time.time() + TIMEOUT)
            if pkt is None:
                log.warning('No ACK for FIN — retrying')
                continue

            if pkt.is_ack():
                # Normal close: peer ACKed our FIN
                log.info('FIN ACKed — connection closed ✓')
                break

            if pkt.is_fin():
                # Simultaneous close: peer sent their FIN at the same time.
                # ACK it so they can exit cleanly, then we are done too.
                log.info(f'Simultaneous FIN received (seq={pkt.seq_num}) '
                         f'— ACKing and closing ✓')
                self._send_ack(pkt.seq_num + 1)
                break

            log.warning(f'Unexpected packet during close: {pkt} — retrying')

        self._connected = False
        log.info('Connection closed')

    def shutdown(self):
        """Hard-close: release the underlying UDP socket."""
        self._connected = False
        try:
            self._udp.close()
        except Exception:
            pass