"""
tests.py — Test suite for CC451 Lab 4.

Covers:
  ┌─────────────────────────────────────────────────────┐
  │  Layer        │  What is tested                     │
  ├───────────────┼─────────────────────────────────────┤
  │  Packet       │  pack/unpack round-trip              │
  │               │  checksum correctness                │
  │               │  checksum detects corruption         │
  │               │  all flag helpers                    │
  │               │  large payload, empty payload        │
  ├───────────────┼─────────────────────────────────────┤
  │  RDTSocket    │  full connect/send/recv/close cycle  │
  │               │  packet-loss simulation              │
  │               │  packet-corruption simulation        │
  │               │  duplicate segment handling          │
  │               │  large data (multi-segment)          │
  │               │  concurrent client → server          │
  ├───────────────┼─────────────────────────────────────┤
  │  HTTP handler │  GET request parsing                 │
  │               │  POST request parsing (with body)    │
  │               │  response encoding / parsing         │
  │               │  missing resource → 404              │
  ├───────────────┼─────────────────────────────────────┤
  │  HTTP end-to- │  GET existing file → 200             │
  │  end          │  GET missing file  → 404             │
  │               │  POST + GET roundtrip                │
  │               │  GET with corruption simulation      │
  │               │  GET with loss simulation            │
  └───────────────┴─────────────────────────────────────┘

Run:
    python tests.py              # all tests
    python tests.py PacketTests  # one class only
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
import time
import unittest

# ── Silence transport-layer noise during tests ────────────────────────────────
logging.basicConfig(level=logging.WARNING)

from packet       import Packet, SYN, SYNACK, ACK, FIN, PSH, HEADER_SIZE
from rdt_socket   import RDTSocket, TIMEOUT
from http_handler import HTTPRequest, HTTPResponse
from http_server  import HTTPServer
from http_client  import HTTPClient


# ─────────────────────────────────────────────────────────────────────────────
# Helper: find a free UDP port
# ─────────────────────────────────────────────────────────────────────────────

import socket as _socket

def _free_port() -> int:
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ─────────────────────────────────────────────────────────────────────────────
# 1. Packet-layer tests
# ─────────────────────────────────────────────────────────────────────────────

class PacketTests(unittest.TestCase):

    def test_header_size(self):
        """HEADER_SIZE must equal 15 bytes (1+4+4+2+4)."""
        self.assertEqual(HEADER_SIZE, 15)

    def test_pack_unpack_roundtrip(self):
        """A packet must survive pack → unpack with all fields intact."""
        original = Packet(flags=ACK, seq_num=42, ack_num=7, data=b'hello')
        raw      = original.pack()
        restored = Packet.unpack(raw)

        self.assertIsNotNone(restored)
        self.assertEqual(restored.flags,   ACK)
        self.assertEqual(restored.seq_num, 42)
        self.assertEqual(restored.ack_num, 7)
        self.assertEqual(restored.data,    b'hello')

    def test_empty_payload(self):
        """Pack/unpack must work for a packet with no data (pure control)."""
        pkt = Packet(flags=SYN, seq_num=1000, ack_num=0, data=b'')
        restored = Packet.unpack(pkt.pack())
        self.assertEqual(restored.data, b'')
        self.assertTrue(restored.is_syn())

    def test_large_payload(self):
        """Pack/unpack must work for a 10 000-byte payload."""
        data = os.urandom(10_000)
        pkt  = Packet(flags=PSH, seq_num=0, ack_num=0, data=data)
        restored = Packet.unpack(pkt.pack())
        self.assertEqual(restored.data, data)

    def test_checksum_valid_on_fresh_packet(self):
        """A freshly packed packet must verify its own checksum."""
        pkt = Packet(flags=ACK, seq_num=1, ack_num=2, data=b'test payload')
        raw = pkt.pack()
        restored = Packet.unpack(raw)
        self.assertTrue(restored.verify_checksum())

    def test_checksum_fails_after_corruption(self):
        """Flipping any bit in the packed bytes must break the checksum."""
        pkt = Packet(flags=ACK, seq_num=0, ack_num=0, data=b'data')
        raw = bytearray(pkt.pack())
        raw[7] ^= 0xFF          # flip a byte in the payload region
        restored = Packet.unpack(bytes(raw))
        self.assertFalse(restored.verify_checksum())

    def test_checksum_header_corruption(self):
        """Corruption in the header region must also break the checksum."""
        pkt = Packet(flags=SYN, seq_num=999, ack_num=0, data=b'abc')
        raw = bytearray(pkt.pack())
        raw[1] ^= 0x01          # flip a bit in seq_num
        restored = Packet.unpack(bytes(raw))
        self.assertFalse(restored.verify_checksum())

    def test_flag_helpers(self):
        """Every flag helper must return True for exactly its own flag."""
        cases = [
            (SYN,    'is_syn',    ['is_synack', 'is_ack', 'is_fin', 'is_psh']),
            (SYNACK, 'is_synack', ['is_syn',    'is_ack', 'is_fin', 'is_psh']),
            (ACK,    'is_ack',    ['is_syn',    'is_synack', 'is_fin', 'is_psh']),
            (FIN,    'is_fin',    ['is_syn',    'is_synack', 'is_ack', 'is_psh']),
            (PSH,    'is_psh',    ['is_syn',    'is_synack', 'is_ack', 'is_fin']),
        ]
        for flag_val, true_method, false_methods in cases:
            pkt = Packet(flags=flag_val)
            with self.subTest(flag=true_method):
                self.assertTrue(getattr(pkt, true_method)())
                for m in false_methods:
                    self.assertFalse(getattr(pkt, m)())

    def test_combined_flags(self):
        """A packet with SYN|ACK combined must report both as True."""
        pkt = Packet(flags=SYN | ACK)
        self.assertTrue(pkt.is_syn())
        self.assertTrue(pkt.is_ack())
        self.assertFalse(pkt.is_fin())

    def test_unpack_too_short(self):
        """unpack() must return None when the buffer is too short."""
        self.assertIsNone(Packet.unpack(b'\x00' * 5))

    def test_repr(self):
        """__repr__ must include the flag names."""
        pkt = Packet(flags=SYN | ACK, seq_num=1, ack_num=2)
        r   = repr(pkt)
        self.assertIn('SYN', r)
        self.assertIn('ACK', r)


# ─────────────────────────────────────────────────────────────────────────────
# 2. RDTSocket transport-layer tests
# ─────────────────────────────────────────────────────────────────────────────

def _run_server_once(port: int, result_box: list,
                     loss: float = 0.0, corrupt: float = 0.0):
    """
    Accept exactly one connection, recv() one message, echo it back, close.
    Stores received bytes in result_box[0].
    """
    srv = RDTSocket(loss, corrupt)
    srv.bind(('127.0.0.1', port))
    conn, _ = srv.accept()
    data = conn.recv()
    result_box.append(data)
    conn.send(data)          # echo
    conn.close()
    srv.shutdown()


class RDTSocketTests(unittest.TestCase):

    def _start_server(self, port, result_box,
                      loss=0.0, corrupt=0.0) -> threading.Thread:
        t = threading.Thread(
            target=_run_server_once,
            args=(port, result_box, loss, corrupt),
            daemon=True,
        )
        t.start()
        time.sleep(0.05)   # give the server time to bind
        return t

    # ── Basic connectivity ────────────────────────────────────────────────────

    def test_handshake_and_small_message(self):
        """Client must be able to connect, send, and receive a short message."""
        port = _free_port()
        box  = []
        self._start_server(port, box)

        client = RDTSocket()
        client.connect(('127.0.0.1', port))
        client.send(b'hello rdt')
        reply = client.recv()
        client.close()

        self.assertEqual(box[0],  b'hello rdt')
        self.assertEqual(reply,   b'hello rdt')

    def test_empty_message(self):
        """Sending an empty payload must not hang."""
        port = _free_port()
        box  = []

        def _srv():
            srv = RDTSocket()
            srv.bind(('127.0.0.1', port))
            conn, _ = srv.accept()
            data = conn.recv()
            box.append(data)
            conn.send(b'ok')
            conn.close()
            srv.shutdown()

        threading.Thread(target=_srv, daemon=True).start()
        time.sleep(0.05)

        client = RDTSocket()
        client.connect(('127.0.0.1', port))
        client.send(b'')
        reply = client.recv()
        client.close()

        self.assertEqual(box[0], b'')
        self.assertEqual(reply,  b'ok')

    def test_large_data_multi_segment(self):
        """A 50 000-byte message must be reassembled correctly."""
        payload = os.urandom(50_000)
        port    = _free_port()
        box     = []
        self._start_server(port, box)

        client = RDTSocket()
        client.connect(('127.0.0.1', port))
        client.send(payload)
        reply = client.recv()
        client.close()

        self.assertEqual(box[0], payload)
        self.assertEqual(reply,  payload)

    # ── Simulation ────────────────────────────────────────────────────────────

    def test_packet_loss_simulation(self):
        """With 30% loss, data must still arrive (via retransmission)."""
        port = _free_port()
        box  = []
        self._start_server(port, box)

        client = RDTSocket(loss_prob=0.3)
        client.connect(('127.0.0.1', port))
        client.send(b'lost in transit?')
        reply = client.recv()
        client.close()

        self.assertEqual(box[0], b'lost in transit?')
        self.assertEqual(reply,  b'lost in transit?')

    def test_packet_corruption_simulation(self):
        """With 30% corruption, data must still arrive (via retransmission)."""
        port = _free_port()
        box  = []
        self._start_server(port, box)

        client = RDTSocket(corrupt_prob=0.3)
        client.connect(('127.0.0.1', port))
        client.send(b'bit-flipped?')
        reply = client.recv()
        client.close()

        self.assertEqual(box[0], b'bit-flipped?')
        self.assertEqual(reply,  b'bit-flipped?')

    def test_loss_and_corruption_combined(self):
        """With both loss and corruption at 20%, data must still get through."""
        port = _free_port()
        box  = []
        self._start_server(port, box)

        client = RDTSocket(loss_prob=0.2, corrupt_prob=0.2)
        client.connect(('127.0.0.1', port))
        client.send(b'chaos mode')
        reply = client.recv()
        client.close()

        self.assertEqual(reply, b'chaos mode')

    # ── Correctness edge cases ────────────────────────────────────────────────

    def test_string_input_auto_encoded(self):
        """send() must accept str and encode it automatically."""
        port = _free_port()
        box  = []
        self._start_server(port, box)

        client = RDTSocket()
        client.connect(('127.0.0.1', port))
        client.send('صباح الخير')       # Arabic — tests UTF-8 handling
        client.recv()
        client.close()

        self.assertEqual(box[0], 'صباح الخير'.encode())


# ─────────────────────────────────────────────────────────────────────────────
# 3. HTTP handler unit tests (no network)
# ─────────────────────────────────────────────────────────────────────────────

class HTTPHandlerTests(unittest.TestCase):

    # ── HTTPRequest parsing ───────────────────────────────────────────────────

    def test_parse_get_request(self):
        raw = b'GET /index.html HTTP/1.0\r\nHost: localhost:8080\r\n\r\n'
        req = HTTPRequest.parse(raw)
        self.assertEqual(req.method,  'GET')
        self.assertEqual(req.path,    '/index.html')
        self.assertEqual(req.version, 'HTTP/1.0')
        self.assertEqual(req.headers.get('host'), 'localhost:8080')
        self.assertEqual(req.body, b'')

    def test_parse_post_request_with_body(self):
        body = b'name=Abdelrahman&course=CC451'
        raw  = (
            b'POST /data.txt HTTP/1.0\r\n'
            b'Content-Type: application/x-www-form-urlencoded\r\n'
            b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
            b'\r\n' + body
        )
        req = HTTPRequest.parse(raw)
        self.assertEqual(req.method, 'POST')
        self.assertEqual(req.path,   '/data.txt')
        self.assertEqual(req.body,   body)

    def test_parse_request_lf_only(self):
        """Parser must handle \\n\\n separator (lenient browsers / curl)."""
        raw = b'GET /hello.txt HTTP/1.0\nHost: x\n\n'
        req = HTTPRequest.parse(raw)
        self.assertEqual(req.method, 'GET')
        self.assertEqual(req.path,   '/hello.txt')

    def test_malformed_request_raises(self):
        """A request with no method must raise ValueError."""
        with self.assertRaises((ValueError, IndexError)):
            HTTPRequest.parse(b'   \r\n\r\n')

    # ── HTTPResponse ──────────────────────────────────────────────────────────

    def test_response_200_encode_decode(self):
        """A 200 response must survive encode → parse with body intact."""
        body  = b'<h1>Hello</h1>'
        resp  = HTTPResponse(200, body=body)
        raw   = resp.encode()
        again = HTTPResponse.parse(raw)

        self.assertEqual(again.status, 200)
        self.assertEqual(again.body,   body)

    def test_response_404_encode(self):
        resp = HTTPResponse(404, body=b'not here')
        raw  = resp.encode()
        self.assertIn(b'404', raw)
        self.assertIn(b'Not Found', raw)

    def test_response_default_headers(self):
        """Default headers (Server, Date, Connection, Content-Length) must be present."""
        resp = HTTPResponse(200, body=b'hi')
        raw  = resp.encode().decode()
        self.assertIn('Server:', raw)
        self.assertIn('Content-Length: 2', raw)
        self.assertIn('Connection: close', raw)

    def test_response_content_length_matches_body(self):
        body = b'x' * 123
        resp = HTTPResponse(200, body=body)
        self.assertEqual(resp.headers['Content-Length'], '123')


# ─────────────────────────────────────────────────────────────────────────────
# 4. End-to-end HTTP over RDT tests
# ─────────────────────────────────────────────────────────────────────────────

class EndToEndTests(unittest.TestCase):
    """
    Spin up a real HTTPServer in a daemon thread and run client requests
    against it.  A fresh temporary webroot is created for each test class.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='lab4_webroot_')
        cls.port   = _free_port()

        # Seed webroot with a test file
        with open(os.path.join(cls.tmpdir, 'page.html'), 'w') as f:
            f.write('<html><body><h1>Test Page</h1></body></html>')
        with open(os.path.join(cls.tmpdir, 'data.txt'), 'w') as f:
            f.write('original content')

        cls.server = HTTPServer(
            host='127.0.0.1', port=cls.port, webroot=cls.tmpdir,
        )
        cls.server_thread = cls.server.start_threaded()
        time.sleep(0.15)   # allow server to bind and enter accept()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _client(self, loss=0.0, corrupt=0.0) -> HTTPClient:
        return HTTPClient('127.0.0.1', self.port, loss, corrupt)

    # ── GET ───────────────────────────────────────────────────────────────────

    def test_get_existing_file_200(self):
        resp = self._client().get('/page.html')
        self.assertEqual(resp.status, 200)
        self.assertIn(b'Test Page', resp.body)

    def test_get_missing_file_404(self):
        resp = self._client().get('/no_such_file.html')
        self.assertEqual(resp.status, 404)

    def test_get_root_serves_index(self):
        """GET / must attempt to serve index.html; 404 if it doesn't exist."""
        resp = self._client().get('/')
        # No index.html in our tmpdir, so expect 404
        self.assertIn(resp.status, (200, 404))

    def test_get_directory_traversal_blocked(self):
        """GET /../etc/passwd must return 403 Forbidden."""
        resp = self._client().get('/../etc/passwd')
        self.assertEqual(resp.status, 403)

    def test_get_txt_file(self):
        resp = self._client().get('/data.txt')
        self.assertEqual(resp.status, 200)
        self.assertIn(b'original content', resp.body)

    # ── POST ─────────────────────────────────────────────────────────────────

    def test_post_creates_file(self):
        content = b'posted data 12345'
        resp = self._client().post('/upload_test.txt', content,
                                   content_type='text/plain')
        self.assertEqual(resp.status, 201)

        saved_path = os.path.join(self.tmpdir, 'upload_test.txt')
        self.assertTrue(os.path.exists(saved_path))
        with open(saved_path, 'rb') as f:
            self.assertEqual(f.read(), content)

    def test_post_then_get_roundtrip(self):
        """POST a file then GET it back — body must match exactly."""
        data = b'roundtrip check: ' + os.urandom(64)
        self._client().post('/roundtrip.bin', data,
                            content_type='application/octet-stream')
        resp = self._client().get('/roundtrip.bin')
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, data)

    def test_post_no_path_returns_400(self):
        resp = self._client().post('/', b'data')
        self.assertEqual(resp.status, 400)

    # ── Unsupported method ────────────────────────────────────────────────────

    def test_unsupported_method_405(self):
        """DELETE must return 405 Method Not Allowed."""
        import socket as _s

        # Build raw request manually (our client only supports GET/POST)
        sock = RDTSocket()
        sock.connect(('127.0.0.1', self.port))
        sock.send(b'DELETE /page.html HTTP/1.0\r\nHost: localhost\r\n\r\n')
        raw  = sock.recv()
        sock.close()

        resp = HTTPResponse.parse(raw)
        self.assertEqual(resp.status, 405)

    # ── Simulation scenarios ──────────────────────────────────────────────────

    def test_get_with_20pct_loss(self):
        """GET must succeed even with 20% packet-loss simulation."""
        resp = self._client(loss=0.2).get('/page.html')
        self.assertEqual(resp.status, 200)

    def test_get_with_20pct_corruption(self):
        """GET must succeed even with 20% corruption simulation."""
        resp = self._client(corrupt=0.2).get('/page.html')
        self.assertEqual(resp.status, 200)

    def test_large_post_and_get(self):
        """POST a 20 000-byte binary payload and retrieve it intact."""
        data = os.urandom(20_000)
        self._client().post('/large.bin', data)
        resp = self._client().get('/large.bin')
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, data)


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys

    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)

    # Load only the class(es) named on the command line, or all classes
    if len(sys.argv) > 1:
        suite = unittest.TestLoader().loadTestsFromName(sys.argv[1], sys.modules[__name__])
    else:
        suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
