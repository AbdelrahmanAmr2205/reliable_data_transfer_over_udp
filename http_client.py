"""
http_client.py — HTTP/1.0 client over RDTSocket.

Supports:
  • GET  – fetch a resource from the server
  • POST – upload data to the server
  • Automatic connection setup / teardown per request (HTTP/1.0 semantics)
  • Optional loss / corruption simulation (forwarded to RDTSocket)
"""

from __future__ import annotations

import logging
import os

from http_handler import HTTPRequest, HTTPResponse
from rdt_socket   import RDTSocket

log = logging.getLogger(__name__)


class HTTPClient:
    """
    HTTP/1.0 client that uses RDTSocket for transport.

    Each request opens a fresh connection, sends the request, receives the
    response, then closes — matching HTTP/1.0's one-request-per-connection model.

    Args:
        host        – server hostname / IP
        port        – server UDP port
        loss_prob   – P(outgoing packet is silently dropped)
        corrupt_prob– P(outgoing packet is bit-corrupted)
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 8080,
                 loss_prob: float = 0.0, corrupt_prob: float = 0.0):
        self.host         = host
        self.port         = port
        self.loss_prob    = loss_prob
        self.corrupt_prob = corrupt_prob

    # ── Public API ────────────────────────────────────────────────────────────

    def get(self, path: str, headers: dict | None = None) -> HTTPResponse:
        """
        Send an HTTP GET request for *path* and return the HTTPResponse.

        Args:
            path    – request path, e.g. '/index.html'
            headers – optional extra headers to include

        Returns:
            HTTPResponse with status, headers, and body.
        """
        raw_request = self._build_request('GET', path, headers)
        return self._transact(raw_request)

    def post(self, path: str, body: bytes | str,
             content_type: str = 'application/octet-stream',
             headers: dict | None = None) -> HTTPResponse:
        """
        Send an HTTP POST request with *body* to *path*.

        Args:
            path         – target resource path, e.g. '/upload.txt'
            body         – payload bytes (or str, which is UTF-8 encoded)
            content_type – value for the Content-Type header
            headers      – optional extra headers

        Returns:
            HTTPResponse with status, headers, and body.
        """
        if isinstance(body, str):
            body = body.encode()

        extra = {
            'Content-Type':   content_type,
            'Content-Length': str(len(body)),
        }
        if headers:
            extra.update(headers)

        raw_request = self._build_request('POST', path, extra, body)
        return self._transact(raw_request)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_request(self, method: str, path: str,
                       extra_headers: dict | None = None,
                       body: bytes = b'') -> bytes:
        """
        Serialise an HTTP/1.0 request to bytes.

        Request format:
            METHOD path HTTP/1.0\r\n
            Host: host:port\r\n
            [extra headers]\r\n
            \r\n
            [body]
        """
        headers: dict[str, str] = {
            'Host':       f'{self.host}:{self.port}',
            'User-Agent': 'RDT-HTTP-Client/1.0 (Python)',
            'Connection': 'close',
        }
        if extra_headers:
            headers.update(extra_headers)

        # Build header block
        request_line = f'{method} {path} HTTP/1.0\r\n'
        hdr_block    = ''.join(f'{k}: {v}\r\n' for k, v in headers.items())
        header_bytes = (request_line + hdr_block + '\r\n').encode()
        return header_bytes + body

    def _transact(self, raw_request: bytes) -> HTTPResponse:
        """
        Open a connection, send *raw_request*, receive the response, close.

        A brand-new RDTSocket is used for each transaction in keeping with
        HTTP/1.0's one-request-per-connection model.
        """
        sock = RDTSocket(self.loss_prob, self.corrupt_prob)
        try:
            log.info(f'Connecting to {self.host}:{self.port} …')
            sock.connect((self.host, self.port))

            log.info(f'Sending request ({len(raw_request)} bytes) …')
            sock.send(raw_request)

            log.info('Waiting for response …')
            raw_response = sock.recv()

            resp = HTTPResponse.parse(raw_response)
            log.info(f'Response: {resp}')
            return resp

        finally:
            sock.close()

    # ── Convenience wrappers ──────────────────────────────────────────────────

    def download(self, path: str, dest: str) -> HTTPResponse:
        """
        GET *path* and save the body to local file *dest*.

        Returns the HTTPResponse so the caller can check the status code.
        """
        resp = self.get(path)
        if resp.status == 200:
            os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
            with open(dest, 'wb') as fh:
                fh.write(resp.body)
            log.info(f'Saved {len(resp.body)} bytes → {dest}')
        return resp

    def upload(self, path: str, src: str,
               content_type: str = 'application/octet-stream') -> HTTPResponse:
        """
        Read local file *src* and POST it to *path* on the server.

        Returns the HTTPResponse.
        """
        with open(src, 'rb') as fh:
            body = fh.read()
        log.info(f'Uploading {src} ({len(body)} bytes) → {path}')
        return self.post(path, body, content_type)
