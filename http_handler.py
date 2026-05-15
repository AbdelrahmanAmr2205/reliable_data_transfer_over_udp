"""
http_handler.py — HTTP/1.0 request and response handling.

Implements:
  • Parsing of GET and POST requests
  • Building HTTP/1.0 responses with correct status lines and headers
  • Status codes: 200, 201, 400, 403, 404, 405, 500
  • Headers: Content-Length, Content-Type, Connection, Date, Server
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing  import Dict, Optional

# ── Constants ─────────────────────────────────────────────────────────────────
HTTP_VERSION = 'HTTP/1.0'

STATUS_REASONS: Dict[int, str] = {
    200: 'OK',
    201: 'Created',
    400: 'Bad Request',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    500: 'Internal Server Error',
}


# ── HTTPRequest ───────────────────────────────────────────────────────────────

class HTTPRequest:
    """
    Parsed HTTP/1.0 request.

    Attributes:
        method  – 'GET' | 'POST'
        path    – request path (e.g. '/index.html')
        version – HTTP version string
        headers – dict of lowercase header names → values
        body    – request body bytes
    """

    def __init__(self, method: str, path: str, version: str,
                 headers: Dict[str, str], body: bytes = b''):
        self.method  = method.upper()
        self.path    = path
        self.version = version
        self.headers = {k.lower(): v.strip() for k, v in headers.items()}
        self.body    = body

    @classmethod
    def parse(cls, raw: bytes) -> 'HTTPRequest':
        """
        Parse raw bytes into an HTTPRequest.

        Splits on \\r\\n\\r\\n (or \\n\\n as fallback) to separate headers from body.
        Uses Content-Length header to determine how many body bytes to keep.

        Raises ValueError if the request line is malformed.
        """
        # Separate header section from body
        for sep in (b'\r\n\r\n', b'\n\n'):
            if sep in raw:
                head_b, body_b = raw.split(sep, 1)
                break
        else:
            head_b, body_b = raw, b''

        head  = head_b.decode('utf-8', errors='replace')
        lines = head.splitlines()

        if not lines:
            raise ValueError('Empty HTTP request')

        # Request line: METHOD PATH VERSION
        parts = lines[0].split()
        if len(parts) < 2:
            raise ValueError(f'Malformed request line: {lines[0]!r}')
        method  = parts[0]
        path    = parts[1]
        version = parts[2] if len(parts) >= 3 else 'HTTP/1.0'

        # Headers
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ':' in line:
                key, _, val = line.partition(':')
                headers[key.strip()] = val.strip()

        # Body (respect Content-Length)
        cl_key = next((k for k in headers if k.lower() == 'content-length'), None)
        if cl_key:
            cl   = int(headers[cl_key])
            body = body_b[:cl]
        else:
            body = body_b

        return cls(method, path, version, headers, body)

    def __repr__(self) -> str:
        return f'HTTPRequest({self.method} {self.path} {self.version})'


# ── HTTPResponse ──────────────────────────────────────────────────────────────

class HTTPResponse:
    """
    HTTP/1.0 response.

    Attributes:
        status  – integer status code (200, 404, …)
        reason  – reason phrase
        headers – dict of header names → values
        body    – response body bytes
    """

    def __init__(self, status: int = 200,
                 headers: Optional[Dict[str, str]] = None,
                 body: bytes = b''):
        self.status  = status
        self.reason  = STATUS_REASONS.get(status, 'Unknown')
        self.headers = dict(headers) if headers else {}
        self.body    = body if isinstance(body, bytes) else body.encode()

        # Inject default headers (only if not already present)
        self.headers.setdefault('Server',         'RDT-HTTP/1.0 (Python)')
        self.headers.setdefault('Date',           _http_date())
        self.headers.setdefault('Content-Length', str(len(self.body)))
        self.headers.setdefault('Content-Type',   'text/html; charset=utf-8')
        self.headers.setdefault('Connection',     'close')

    def encode(self) -> bytes:
        """Serialise to wire format: status-line + headers + CRLF + body."""
        status_line = f'{HTTP_VERSION} {self.status} {self.reason}\r\n'
        hdr_block   = ''.join(f'{k}: {v}\r\n' for k, v in self.headers.items())
        return (status_line + hdr_block + '\r\n').encode() + self.body

    @classmethod
    def parse(cls, raw: bytes) -> 'HTTPResponse':
        """Parse raw bytes (e.g. received from server) into an HTTPResponse."""
        for sep in (b'\r\n\r\n', b'\n\n'):
            if sep in raw:
                head_b, body_b = raw.split(sep, 1)
                break
        else:
            head_b, body_b = raw, b''

        head  = head_b.decode('utf-8', errors='replace')
        lines = head.splitlines()

        # Status line: VERSION STATUS_CODE REASON
        parts  = lines[0].split(None, 2) if lines else []
        status = int(parts[1]) if len(parts) >= 2 else 500

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ':' in line:
                key, _, val = line.partition(':')
                headers[key.strip()] = val.strip()

        return cls(status, headers, body_b)

    def __repr__(self) -> str:
        return f'HTTPResponse({self.status} {self.reason}, {len(self.body)}B)'


# ── Helpers ───────────────────────────────────────────────────────────────────

def _http_date() -> str:
    """Return current UTC time in HTTP-date format (RFC 7231 §7.1.1.1)."""
    return datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
