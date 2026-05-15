# Reliable Data Transfer (RDT) over UDP

This repository contains a Python implementation of a reliable transport protocol built on top of UDP, designed for the CC451-Computer Networks Lab 4, Spring 2026 course at Alexandria University. 

**Author:** Abdelrahman Amr

## Overview
The goal of this project is to simulate TCP-like reliability over a connectionless UDP socket. It extends the user space by implementing an HTTP/1.0 protocol on top of this custom reliable transport layer.

## Features
* **Stop-and-Wait Protocol:** Ensures reliable delivery by sending one packet and waiting for an acknowledgment before sending the next.
* **Connection Management:** Implements a three-way handshake (SYN, SYNACK, ACK) for connection establishment and a FIN/ACK teardown sequence.
* **Error Detection:** Uses a 16-bit ones-complement checksum (RFC 1071) calculated over the packet header and data. Packets with invalid checksums are automatically dropped.
* **Simulations:** Includes built-in methods to simulate packet loss and bit-level corruption to test the timeout and retransmission mechanisms.
* **HTTP/1.0 Support:** Features a custom `HTTPServer` and `HTTPClient` that parse and handle standard GET and POST requests. It supports standard headers and status codes, including 200 OK and 404 Not Found.
* **TCP Bridge (Bonus):** A proxy bridge (`tcp_bridge.py`) that translates standard TCP traffic to the custom RDT/UDP protocol, allowing the server to be accessed by real web browsers and analyzed in Wireshark.
* **Unit Testing (Bonus):** A comprehensive test suite (`tests.py`) covering the packet, socket, and HTTP layers.

## Project Structure
* `packet.py` — Defines the custom packet header format (15 bytes) including sequence numbers, acknowledgments, flags, and checksum calculation.
* `rdt_socket.py` — The core transport layer simulating TCP semantics (handshake, stop-and-wait, retransmission) over `socket.SOCK_DGRAM`.
* `http_handler.py` — Parses raw bytes into structured `HTTPRequest` and `HTTPResponse` objects.
* `http_server.py` & `run_server.py` — The server application that handles incoming requests and serves static files from the `webroot/` directory.
* `http_client.py` & `run_client.py` — A command-line client to execute GET and POST requests.
* `tcp_bridge.py` — A proxy allowing standard TCP clients (like web browsers) to communicate with the RDT server.
* `tests.py` — Contains the test suite for validating all application layers.

## Usage

### Starting the Server
By default, the server binds to `127.0.0.1:8080` and serves files from the `webroot` directory:
```bash
python run_server.py

```

You can simulate network unreliability by adding arguments for packet loss and corruption probabilities:

```bash
python run_server.py --loss 0.2 --corrupt 0.1

```

### Using the Client

To perform a GET request:

```bash
python run_client.py GET /index.html

```

To upload data via POST:

```bash
python run_client.py POST /upload.txt --body "Hello from the client"

```

### Testing with a Web Browser (Bonus Feature)

To test the server using a standard web browser:

1. Start the HTTP server: `python run_server.py`
2. Start the TCP bridge in a new terminal: `python tcp_bridge.py`
3. Open a browser and navigate to `http://localhost:9090`

### Running the Tests

Execute the included test suite to verify the protocol's reliability under various simulated network conditions:

```bash
python tests.py

```
