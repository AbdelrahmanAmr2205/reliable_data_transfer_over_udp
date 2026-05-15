#!/usr/bin/env python3
"""
run_server.py — Start the RDT HTTP Server.

Usage:
    python run_server.py [--host HOST] [--port PORT]
                         [--loss PROB] [--corrupt PROB]
                         [--webroot DIR]

Defaults:
    host    = 127.0.0.1
    port    = 8080
    loss    = 0.0   (no packet loss)
    corrupt = 0.0   (no corruption)
    webroot = ./webroot
"""

import argparse
import logging

from http_server import HTTPServer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SERVER] %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
)

def main():
    p = argparse.ArgumentParser(description='RDT HTTP/1.0 Server')
    p.add_argument('--host',    default='127.0.0.1')
    p.add_argument('--port',    type=int,   default=8080)
    p.add_argument('--loss',    type=float, default=0.0,
                   help='Packet-loss probability 0.0–1.0')
    p.add_argument('--corrupt', type=float, default=0.0,
                   help='Corruption probability 0.0–1.0')
    p.add_argument('--webroot', default='webroot')
    args = p.parse_args()

    srv = HTTPServer(args.host, args.port, args.webroot,
                     args.loss, args.corrupt)
    try:
        srv.start()
    except KeyboardInterrupt:
        print('\nServer stopped.')

if __name__ == '__main__':
    main()
