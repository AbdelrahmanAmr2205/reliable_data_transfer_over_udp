"""
http_server.py — HTTP/1.0 server over RDTSocket.

Features:
  • GET  – serve static files from webroot (200 OK / 404 Not Found)
  • POST – write body to a file under webroot (201 Created)
  • Directory-traversal protection
  • Runs sequentially (one connection at a time, matching HTTP/1.0 semantics)
  • Optional loss / corruption simulation (forwarded to RDTSocket)
"""

from __future__ import annotations

import logging
import mimetypes
import os
import threading

from http_handler import HTTPRequest, HTTPResponse
from rdt_socket   import RDTSocket

log = logging.getLogger(__name__)

_HERE    = os.path.dirname(os.path.abspath(__file__))
WEBROOT  = os.path.join(_HERE, 'webroot')


class HTTPServer:
    """
    HTTP/1.0 server that uses RDTSocket for transport.

    Args:
        host        – bind address (default 127.0.0.1)
        port        – UDP port (default 8080)
        webroot     – directory to serve files from
        loss_prob   – forwarded to RDTSocket; P(packet lost)
        corrupt_prob– forwarded to RDTSocket; P(packet corrupted)
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 8080,
                 webroot: str = WEBROOT,
                 loss_prob: float = 0.0, corrupt_prob: float = 0.0):
        self.host         = host
        self.port         = port
        self.webroot      = os.path.abspath(webroot)
        self.loss_prob    = loss_prob
        self.corrupt_prob = corrupt_prob
        self._running     = False
        os.makedirs(self.webroot, exist_ok=True)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        """Block and serve connections sequentially (HTTP/1.0 model)."""
        srv = RDTSocket(self.loss_prob, self.corrupt_prob)
        srv.bind((self.host, self.port))
        self._running = True
        log.info(f'HTTP Server listening on udp://{self.host}:{self.port}  '
                 f'webroot={self.webroot}')
        log.info(f'  loss={self.loss_prob:.0%}  corrupt={self.corrupt_prob:.0%}')

        try:
            while self._running:
                try:
                    conn, addr = srv.accept()
                    log.info(f'Connection from {addr}')
                    self._serve(conn, addr)
                except KeyboardInterrupt:
                    break
                except Exception as exc:
                    log.error(f'accept() error: {exc}', exc_info=True)
        finally:
            srv.shutdown()
            log.info('Server shut down')

    def start_threaded(self) -> threading.Thread:
        """Start server in a daemon thread; returns the thread."""
        t = threading.Thread(target=self.start, daemon=True, name='HTTPServer')
        t.start()
        return t

    def stop(self):
        self._running = False

    # ── Request dispatch ──────────────────────────────────────────────────────

    def _serve(self, conn: RDTSocket, addr: tuple):
        """Handle one HTTP request/response exchange."""
        try:
            raw = conn.recv()
            if not raw:
                log.warning(f'Empty request from {addr}')
                return

            req  = HTTPRequest.parse(raw)
            log.info(f'→ {req}')
            resp = self._dispatch(req)
            log.info(f'← {resp}')
            conn.send(resp.encode())

        except ConnectionResetError as exc:
            # Client disconnected mid-transfer (e.g. closed before response
            # was fully sent). Not a server bug — log as warning only.
            log.warning(f'Client {addr} reset the connection: {exc}')
        except Exception as exc:
            log.error(f'Error serving {addr}: {exc}', exc_info=True)
            try:
                conn.send(HTTPResponse(500, body=b'<h1>500 Internal Server Error</h1>').encode())
            except Exception:
                pass
        finally:
            conn.close()

    def _dispatch(self, req: HTTPRequest) -> HTTPResponse:
        if req.method == 'GET':
            return self._handle_get(req)
        if req.method == 'POST':
            return self._handle_post(req)
        return HTTPResponse(405,
                            headers={'Allow': 'GET, POST'},
                            body=b'<h1>405 Method Not Allowed</h1>')

    # ── GET ───────────────────────────────────────────────────────────────────

    def _handle_get(self, req: HTTPRequest) -> HTTPResponse:
        rel  = req.path.lstrip('/')
        rel  = rel or 'index.html'            # bare '/' → index.html
        path = self._safe_path(rel)

        if path is None:
            return HTTPResponse(403, body=b'<h1>403 Forbidden</h1>')

        if not os.path.isfile(path):
            body = (f'<html><body>'
                    f'<h1>404 Not Found</h1>'
                    f'<p>The requested resource <code>/{rel}</code> '
                    f'does not exist on this server.</p>'
                    f'</body></html>').encode()
            return HTTPResponse(404, body=body)

        mime, _ = mimetypes.guess_type(path)
        with open(path, 'rb') as fh:
            data = fh.read()

        return HTTPResponse(
            200,
            headers={'Content-Type': mime or 'application/octet-stream'},
            body=data,
        )

    # ── POST ──────────────────────────────────────────────────────────────────

    def _handle_post(self, req: HTTPRequest) -> HTTPResponse:
        rel = req.path.lstrip('/')
        if not rel:
            return HTTPResponse(400, body=b'<h1>400 Bad Request</h1>'
                                         b'<p>POST requires a resource path.</p>')

        path = self._safe_path(rel)
        if path is None:
            return HTTPResponse(403, body=b'<h1>403 Forbidden</h1>')

        os.makedirs(os.path.dirname(path) or self.webroot, exist_ok=True)
        with open(path, 'wb') as fh:
            fh.write(req.body)

        body = (f'<html><body>'
                f'<h1>201 Created</h1>'
                f'<p>Resource <code>/{rel}</code> saved '
                f'({len(req.body)} bytes).</p>'
                f'</body></html>').encode()
        return HTTPResponse(201, body=body)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _safe_path(self, rel: str) -> str | None:
        """
        Resolve *rel* within webroot.
        Returns the absolute path, or None if it would escape webroot.
        """
        path = os.path.normpath(os.path.join(self.webroot, rel))
        if not path.startswith(self.webroot + os.sep) and path != self.webroot:
            log.warning(f'Directory traversal attempt: {rel!r}')
            return None
        return path