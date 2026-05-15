"""
tcp_bridge.py — TCP ↔ RDT/UDP bridge  (Browser Bonus).

A real web browser speaks TCP.  Our HTTP server speaks RDT-over-UDP.
This bridge sits in the middle:

    Browser ──TCP──→ Bridge ──RDT/UDP──→ HTTP Server
    Browser ←─TCP── Bridge ←──RDT/UDP── HTTP Server

How it works:
  1. The bridge binds a real TCP server socket on BRIDGE_PORT (default 9090).
  2. The browser connects to localhost:9090 as if it were a normal web server.
  3. For each TCP connection the bridge:
       a. Reads the full HTTP request from the browser over TCP.
       b. Opens a fresh RDTSocket and connects to the RDT HTTP server.
       c. Sends the request through RDTSocket.
       d. Receives the response through RDTSocket.
       e. Writes the response back to the browser over TCP.
  4. The TCP connection is closed after each response (HTTP/1.0 semantics).

Usage:
    # Terminal 1 – start the RDT HTTP server
    python http_server.py

    # Terminal 2 – start the bridge
    python tcp_bridge.py

    # Browser – navigate to http://localhost:9090/index.html
"""

from __future__ import annotations

import logging
import socket
import threading

from rdt_socket import RDTSocket

log = logging.getLogger(__name__)

BRIDGE_PORT  = 9090           # TCP port the browser connects to
RDT_HOST     = '127.0.0.1'   # where our RDT HTTP server lives
RDT_PORT     = 8080
BACKLOG      = 5
TCP_BUF      = 65536


class TCPBridge:
    """
    Listens for real TCP connections (e.g. from a browser) and forwards
    each HTTP/1.0 request to our RDT-over-UDP server, then relays the
    response back.

    Args:
        bridge_host – address to bind the TCP listener (default '127.0.0.1')
        bridge_port – TCP port to listen on  (default 9090)
        rdt_host    – RDT HTTP server address (default '127.0.0.1')
        rdt_port    – RDT HTTP server port    (default 8080)
    """

    def __init__(self,
                 bridge_host: str = '127.0.0.1',
                 bridge_port: int = BRIDGE_PORT,
                 rdt_host:    str = RDT_HOST,
                 rdt_port:    int = RDT_PORT):
        self.bridge_host = bridge_host
        self.bridge_port = bridge_port
        self.rdt_host    = rdt_host
        self.rdt_port    = rdt_port
        self._running    = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        """Block and accept TCP connections, forwarding each to the RDT server."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bridge_host, self.bridge_port))
        srv.listen(BACKLOG)
        self._running = True

        log.info(
            f'TCP↔RDT Bridge ready on tcp://{self.bridge_host}:{self.bridge_port}'
            f'  →  udp://{self.rdt_host}:{self.rdt_port}'
        )
        log.info(f'Point your browser at  http://{self.bridge_host}:{self.bridge_port}/')

        try:
            while self._running:
                try:
                    conn, addr = srv.accept()
                    log.info(f'Browser connected from {addr}')
                    t = threading.Thread(
                        target=self._handle,
                        args=(conn, addr),
                        daemon=True,
                        name=f'bridge-{addr}',
                    )
                    t.start()
                except KeyboardInterrupt:
                    break
                except Exception as exc:
                    log.error(f'accept error: {exc}', exc_info=True)
        finally:
            srv.close()
            log.info('Bridge shut down')

    def stop(self):
        self._running = False

    def start_threaded(self) -> threading.Thread:
        t = threading.Thread(target=self.start, daemon=True, name='TCPBridge')
        t.start()
        return t

    # ── Per-connection handler ────────────────────────────────────────────────

    def _handle(self, tcp_conn: socket.socket, addr: tuple):
        """
        Read one HTTP request from the browser over TCP, relay it through the
        RDT socket to the HTTP server, and write the response back over TCP.
        """
        try:
            # ── 1. Read HTTP request from browser ─────────────────────────────
            raw = self._tcp_recv(tcp_conn)
            if not raw:
                log.warning(f'Empty request from browser {addr}')
                return
            log.info(f'Browser request ({len(raw)} bytes):')
            log.info(raw.decode('utf-8', errors='replace').splitlines()[0])

            # ── 2. Forward to RDT HTTP server ────────────────────────────────
            rdt = RDTSocket()
            try:
                rdt.connect((self.rdt_host, self.rdt_port))
                rdt.send(raw)
                response_bytes = rdt.recv()
            finally:
                rdt.close()

            # ── 3. Relay response back to browser over TCP ───────────────────
            log.info(f'Server response ({len(response_bytes)} bytes) → browser')
            tcp_conn.sendall(response_bytes)

        except Exception as exc:
            log.error(f'Bridge error for {addr}: {exc}', exc_info=True)
            # Send a minimal error response so the browser doesn't hang
            error_resp = (
                b'HTTP/1.0 502 Bad Gateway\r\n'
                b'Content-Type: text/html\r\n'
                b'Connection: close\r\n'
                b'\r\n'
                b'<h1>502 Bad Gateway</h1>'
                b'<p>The RDT server could not be reached.</p>'
            )
            try:
                tcp_conn.sendall(error_resp)
            except Exception:
                pass
        finally:
            tcp_conn.close()

    # ── TCP receive helper ────────────────────────────────────────────────────

    @staticmethod
    def _tcp_recv(conn: socket.socket, timeout: float = 5.0) -> bytes:
        """
        Read a complete HTTP request from a TCP connection.

        Reads until we see the blank line that terminates the headers
        (\\r\\n\\r\\n) and then reads exactly Content-Length body bytes
        (if present).  Falls back to a timeout-based drain so the bridge
        works even with browsers that don't send Content-Length.
        """
        conn.settimeout(timeout)
        buf = b''

        # Phase 1: read until end-of-headers
        while b'\r\n\r\n' not in buf and b'\n\n' not in buf:
            try:
                chunk = conn.recv(TCP_BUF)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk

        # Phase 2: read body bytes according to Content-Length (POST support)
        header_end = buf.find(b'\r\n\r\n')
        if header_end == -1:
            header_end = buf.find(b'\n\n')
            sep_len = 2
        else:
            sep_len = 4

        if header_end != -1:
            header_part = buf[:header_end].decode('utf-8', errors='replace')
            body_so_far = buf[header_end + sep_len:]

            # Extract Content-Length
            cl = 0
            for line in header_part.splitlines()[1:]:
                if line.lower().startswith('content-length:'):
                    try:
                        cl = int(line.split(':', 1)[1].strip())
                    except ValueError:
                        pass
                    break

            # Read remaining body bytes
            while len(body_so_far) < cl:
                try:
                    chunk = conn.recv(min(TCP_BUF, cl - len(body_so_far)))
                except socket.timeout:
                    break
                if not chunk:
                    break
                body_so_far += chunk

            buf = buf[:header_end + sep_len] + body_so_far

        return buf


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [BRIDGE] %(levelname)s %(message)s',
        datefmt='%H:%M:%S',
    )
    bridge = TCPBridge()
    bridge.start()
