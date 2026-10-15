#!/usr/bin/env python3
"""Minimal host for the ardopcf socket audio device (TCP:<port>).

Listens on 127.0.0.1:<port>, accepts ardopcf's audio connection, sends
silence as RX audio in real time, prints the length of each transmission and
acknowledges it ('D') as soon as ardopcf ends it ('E'). A real host would
send the samples to its radio and acknowledge only after they have been
transmitted.

    python3 netaudio_loopback.py 8600 &
    ardopcf -i TCP:8600 -o TCP:8600 8515

Message format: type (1 byte) | payload length (uint32 little endian) | payload.
'E' and 'D' carry the transmission number (uint32 LE).  Run ardopcf with
ARDOPCF_NETAUDIO_TOKEN set (required), run this script with the same variable.
"""

import hashlib
import hmac
import os
import socket
import struct
import sys
import threading
import time

HEADER = struct.Struct("<cI")
RATE = 12000


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def send(conn, lock, kind, payload=b""):
    with lock:
        conn.sendall(HEADER.pack(kind, len(payload)) + payload)


def rx_clock(conn, lock):
    block = bytes(2 * RATE // 50)  # 20 ms of silence
    next_t = time.monotonic()
    while True:
        send(conn, lock, b"R", block)
        next_t += 0.02
        time.sleep(max(0.0, next_t - time.monotonic()))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8600
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    conn, _ = server.accept()
    lock = threading.Lock()
    # Protocol 3 handshake: prove knowledge of ARDOPCF_NETAUDIO_TOKEN (the same
    # value as in ardopcf's environment) without sending it.
    key = os.environ["ARDOPCF_NETAUDIO_TOKEN"].encode()
    nonce1 = os.urandom(32)
    send(conn, lock, b"N", nonce1)
    kind, length = HEADER.unpack(recv_exact(conn, HEADER.size))
    parts = recv_exact(conn, length).decode().split()
    if kind != b"H" or not hmac.compare_digest(
            bytes.fromhex(parts[4]), hmac.new(key, nonce1 + b"engine", hashlib.sha256).digest()):
        sys.exit("ardopcf did not authenticate")
    send(conn, lock, b"P", hmac.new(key, bytes.fromhex(parts[3]) + b"bridge",
                                    hashlib.sha256).digest())
    print("hello:", " ".join(parts[:3]))
    threading.Thread(target=rx_clock, args=(conn, lock), daemon=True).start()
    samples = 0
    try:
        while True:
            kind, length = HEADER.unpack(recv_exact(conn, HEADER.size))
            payload = recv_exact(conn, length) if length else b""
            if kind == b"T":
                samples += length // 2
            elif kind == b"E":
                print("transmission %d: %.3f s" % (struct.unpack("<I", payload)[0],
                                                   samples / float(RATE)))
                samples = 0
                send(conn, lock, b"D", payload)  # acknowledge this transmission
    except (EOFError, OSError):
        pass


if __name__ == "__main__":
    main()
