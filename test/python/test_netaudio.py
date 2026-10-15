#! /usr/bin/python
"""
Tests of the socket audio device (TCP:<port>) and of the host port hardening.

They start the ardopcf executable (repository root, or $ARDOPCF) with the
socket audio device and act as the host program over loopback TCP.  Nothing
here uses a sound card or the network beyond 127.0.0.1 (one test also tries
the computer's own non-loopback address to show the host ports are not
reachable there).

Run with:  python test_netaudio.py      or      pytest test_netaudio.py
"""

import os
import socket
import struct
import subprocess
import sys
import time

HEADER = struct.Struct("<cI")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def binary():
    env = os.environ.get("ARDOPCF")
    if env:
        return env
    for cand in (os.path.join(ROOT, "ardopcf"), os.path.join(ROOT, "build", "macos", "ardopcf"),
                 os.path.join(ROOT, "build", "linux", "ardopcf")):
        if os.path.exists(cand):
            return cand
    raise RuntimeError("ardopcf executable not found (set ARDOPCF)")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_pair():
    while True:
        p = free_port()
        try:
            with socket.socket() as s:
                s.bind(("127.0.0.1", p + 1))
            return p
        except OSError:
            continue


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def lan_address():
    """This computer's non-loopback IPv4 address (no packet is sent), or None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            addr = s.getsockname()[0]
        return None if addr.startswith("127.") else addr
    except OSError:
        return None


class Tnc:
    """ardopcf with the socket audio device and a host on both ends."""

    def __init__(self, token=None, extra=(), audio_dev=None, rcvbuf=None, out_dev=None,
                 accept_audio=True):
        self.audio = socket.socket()
        self.audio.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if rcvbuf:
            self.audio.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        self.audio.bind(("127.0.0.1", 0))
        self.audio.listen(2)
        self.aport = self.audio.getsockname()[1]
        self.hport = free_pair()
        dev = audio_dev or "TCP:%d" % self.aport
        env = dict(os.environ)
        env.pop("ARDOPCF_NETAUDIO_TOKEN", None)
        if token is not None:
            env["ARDOPCF_NETAUDIO_TOKEN"] = token
        self.proc = subprocess.Popen(
            [binary(), "-m", "-G", "0", "-H", "LISTEN FALSE", "-i", dev, "-o", out_dev or dev]
            + list(extra) + [str(self.hport)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        self.conn = None
        if accept_audio:
            self.audio.settimeout(5)
            try:
                self.conn, _ = self.audio.accept()
            except socket.timeout:
                self.conn = None
        self.cmd = None
        self.lines = []

    def send(self, kind, payload=b""):
        self.conn.sendall(HEADER.pack(kind, len(payload)) + payload)

    def read_msg(self, timeout=5):
        self.conn.settimeout(timeout)
        kind, length = HEADER.unpack(recv_exact(self.conn, HEADER.size))
        return kind, recv_exact(self.conn, length) if length else b""

    def connect_host(self):
        deadline = time.monotonic() + 5
        while True:
            try:
                self.cmd = socket.create_connection(("127.0.0.1", self.hport), timeout=1)
                return self.cmd
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.1)

    def command(self, text):
        self.cmd.sendall(text.encode() + b"\r")

    def wait_line(self, prefix, timeout):
        deadline = time.monotonic() + timeout
        buf = b""
        self.cmd.settimeout(0.1)
        while time.monotonic() < deadline:
            for line in self.lines:
                if line.startswith(prefix):
                    self.lines.remove(line)
                    return time.monotonic(), line
            try:
                chunk = self.cmd.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
            while b"\r" in buf:
                line, buf = buf.split(b"\r", 1)
                self.lines.append(line.decode(errors="replace"))
        return None, None

    def close(self):
        for s in (self.cmd, self.conn, self.audio):
            if s is not None:
                s.close()
        self.proc.terminate()
        try:
            out, _ = self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, _ = self.proc.communicate()
        return out.decode(errors="replace")


def _rx_silence(tnc, seconds):
    block = bytes(480)
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        tnc.send(b"R", block)
        time.sleep(0.02)


def _burst(tnc, frame, ack=None, timeout=15):
    """TXFRAME; collect T until E; reply D per *ack*; return (ptt_s, samples, seq)."""
    tnc.command("TXFRAME " + frame)
    samples = 0
    seq = None
    deadline = time.monotonic() + timeout
    t_end = None
    while time.monotonic() < deadline:
        kind, payload = tnc.read_msg(timeout=timeout)
        if kind == b"T":
            samples += len(payload) // 2
        elif kind == b"E":
            seq = struct.unpack("<I", payload)[0]
            t_end = time.monotonic()
            if ack == "now":
                tnc.send(b"D", struct.pack("<I", seq))
            elif ack == "stale":
                tnc.send(b"D", struct.pack("<I", seq - 1))
            break
    t_on, _ = tnc.wait_line("PTT TRUE", 1)
    t_off, _ = tnc.wait_line("PTT FALSE", timeout)
    return (t_off - t_end) if (t_off and t_end) else None, samples, seq


def test_host_ports_loopback_only():
    """Host ports listen on 127.0.0.1 only (not on the LAN address)."""
    tnc = Tnc()
    try:
        tnc.connect_host()
        lan = lan_address()
        if lan:
            for port in (tnc.hport, tnc.hport + 1):
                s = socket.socket()
                s.settimeout(1)
                try:
                    assert s.connect_ex((lan, port)) != 0, "host port reachable on " + lan
                finally:
                    s.close()
    finally:
        tnc.close()


def test_second_host_connection_refused():
    """A second control or data connection is closed; the first keeps working."""
    tnc = Tnc()
    try:
        tnc.connect_host()
        data = socket.create_connection(("127.0.0.1", tnc.hport + 1), timeout=2)
        time.sleep(0.3)
        for port in (tnc.hport, tnc.hport + 1):
            extra = socket.create_connection(("127.0.0.1", port), timeout=2)
            extra.settimeout(2)
            assert extra.recv(10) == b""  # closed by ardopcf
            extra.close()
        tnc.command("MYCALL DG6FL")
        _, line = tnc.wait_line("MYCALL", 3)
        assert line is not None
        data.close()
    finally:
        tnc.close()


def test_token_required_when_set():
    """With ARDOPCF_NETAUDIO_TOKEN set, a host without the token gets nothing."""
    tnc = Tnc(token="s3cret-token")
    try:
        assert tnc.conn is not None
        tnc.conn.settimeout(5)
        assert tnc.conn.recv(100) == b""  # no hello, closed after 3 s
    finally:
        out = tnc.close()
    assert "did not authenticate" in out


def test_token_accepted():
    """The right token is answered with a hello that echoes it."""
    tnc = Tnc(token="s3cret-token")
    try:
        tnc.send(b"A", b"s3cret-token")
        kind, hello = tnc.read_msg()
        assert kind == b"H" and hello == b"ARDOPCF-NETAUDIO 2 12000 s3cret-token"
    finally:
        tnc.close()


def test_non_loopback_audio_host_refused():
    """TCP:<host>:<port> with a non-loopback host is refused."""
    lan = lan_address() or "192.0.2.1"
    tnc = Tnc(audio_dev="TCP:%s:%d" % (lan, free_port()), accept_audio=False)
    try:
        time.sleep(1.0)
    finally:
        out = tnc.close()
    assert "not a loopback address" in out


def test_different_capture_playback_refused():
    """-i and -o naming different sockets: playback is refused."""
    tnc = Tnc(out_dev="TCP:%d" % free_port())
    try:
        time.sleep(0.5)
    finally:
        out = tnc.close()
    assert "must use the same socket" in out


def test_early_d_waits_for_transmission_length():
    """A D sent at once is honoured only after the transmission's duration."""
    tnc = Tnc()
    try:
        tnc.read_msg()  # hello
        tnc.connect_host()
        tnc.command("MYCALL DG6FL")
        tail, samples, seq = _burst(tnc, '4FSK.2000.600.E "X" 0x3F', ack="now")
        assert seq == 1 and samples > 5 * 12000
        # PTT FALSE no earlier than the paced end of the audio (lead 0.5 s)
        assert tail is not None and tail >= 0.3
        tail2, _, seq2 = _burst(tnc, "DataACK 80 0x3F", ack="now")
        assert seq2 == 2
    finally:
        tnc.close()


def test_stale_d_ignored_and_wall_clock_timeout():
    """A D for the previous transmission is ignored; timeout = length + 2 s wall clock."""
    tnc = Tnc()
    try:
        tnc.read_msg()
        tnc.connect_host()
        tnc.command("MYCALL DG6FL")
        tail, samples, seq = _burst(tnc, "DataACK 80 0x3F", ack="stale")
        length = samples / 12000.0
        # flush started at E; the timeout is length + 2 s of wall clock
        assert tail is not None and 1.5 <= tail <= length + 2.6
    finally:
        tnc.close()


def test_stalled_host_drops_ptt_and_reports_fault():
    """A host that stops reading: PTT drops and a FAULT is reported, bounded by the
    transmission length + 2 s (send stall, or missing drain acknowledgement when the
    socket buffers absorb the whole frame)."""
    tnc = Tnc(rcvbuf=4096)
    try:
        tnc.read_msg()
        tnc.connect_host()
        tnc.command("MYCALL DG6FL")
        tnc.command('TXFRAME 4FSK.2000.600.E "X" 0x3F')
        t_on, _ = tnc.wait_line("PTT TRUE", 5)
        assert t_on is not None
        t_off, _ = tnc.wait_line("PTT FALSE", 12)
        t_fault, line = tnc.wait_line("FAULT Socket audio", 2)
        assert t_fault is not None, line
        assert t_off is not None and t_off - t_on < 5.6 + 2.6
    finally:
        tnc.close()


def test_connection_loss_reported():
    """Closing the audio connection reports a FAULT to the host."""
    tnc = Tnc()
    try:
        tnc.read_msg()
        tnc.connect_host()
        _rx_silence(tnc, 0.3)
        tnc.conn.close()
        tnc.conn = None
        t, line = tnc.wait_line("FAULT Socket audio connection lost", 5)
        assert t is not None
    finally:
        tnc.close()


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except Exception as exc:  # noqa: BLE001 - report and continue
                failed += 1
                print("FAIL", name, repr(exc))
    sys.exit(1 if failed else 0)
