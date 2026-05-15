#!/usr/bin/env python3
"""
run_client.py — Send a single HTTP request using the RDT client.

Usage:
    python run_client.py GET  /index.html
    python run_client.py POST /upload.txt  --body "hello server"
    python run_client.py POST /file.bin    --file ./local.bin
    python run_client.py GET  /page.html   --loss 0.2 --corrupt 0.1

Options:
    --host    SERVER IP    (default 127.0.0.1)
    --port    SERVER PORT  (default 8080)
    --loss    drop prob    (default 0.0)
    --corrupt corrupt prob (default 0.0)
    --body    POST body string
    --file    path to local file to upload (POST)
"""

import argparse
import logging
import sys

from http_client import HTTPClient

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [CLIENT] %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
)

def main():
    p = argparse.ArgumentParser(description='RDT HTTP/1.0 Client')
    p.add_argument('method', choices=['GET', 'POST'])
    p.add_argument('path')
    p.add_argument('--host',    default='127.0.0.1')
    p.add_argument('--port',    type=int,   default=8080)
    p.add_argument('--loss',    type=float, default=0.0)
    p.add_argument('--corrupt', type=float, default=0.0)
    p.add_argument('--body',    default='')
    p.add_argument('--file',    default='')
    args = p.parse_args()

    client = HTTPClient(args.host, args.port, args.loss, args.corrupt)

    if args.method == 'GET':
        resp = client.get(args.path)
    else:   # POST
        if args.file:
            resp = client.upload(args.path, args.file)
        else:
            resp = client.post(args.path, args.body.encode(),
                               content_type='text/plain')

    print(f'\n─── Response: {resp.status} {resp.reason} ───')
    for k, v in resp.headers.items():
        print(f'{k}: {v}')
    print()
    try:
        print(resp.body.decode())
    except UnicodeDecodeError:
        print(f'<binary body: {len(resp.body)} bytes>')

if __name__ == '__main__':
    main()
