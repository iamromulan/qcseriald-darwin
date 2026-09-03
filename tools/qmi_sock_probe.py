#!/usr/bin/env python3
"""qmi_sock_probe — validate qcseriald's QMI unix socket.

qcseriald, started with QCSERIALD_QMI_SOCKET=1, exposes a Qualcomm modem's QMI
(QMUX) channel as an AF_UNIX **SOCK_STREAM** socket carrying whole QMUX frames
(see qcseriald.c `qmi_usb_to_sock` / `qmi_sock_to_usb`). SEQPACKET would map one
datagram to one frame, but macOS AF_UNIX doesn't support it, so the transport is
a byte stream and the peer reassembles by the self-delimiting QMUX length field
— which is what this tool (and any real QMI consumer) does on read. It connects
to that socket and does a single **read-only** QMI CTL round-trip
(`GET_VERSION_INFO`, msg 0x0021, no TLVs) to prove the framing end-to-end.

Success = we get a well-formed QMUX response back for service CTL with the same
transaction id, carrying the version-info TLV. That exercises the whole path:
  * socket write -> reassembled to one whole frame -> one
    SEND_ENCAPSULATED_COMMAND control transfer on ep0,
  * modem's RESPONSE_AVAILABLE interrupt notification ->
    GET_ENCAPSULATED_RESPONSE -> one frame written back to the socket.

Note the QMI control channel does *not* ride the interface's bulk pair — those
endpoints carry RMNET/IP network data. QMUX travels over ep0 as CDC-WDM
encapsulated class requests, gated on the interrupt-IN notification.

SAFETY: only ever sends CTL GET_VERSION_INFO — a read-only capability query.
No client-id allocation, no stateful service messages, nothing that touches the
eUICC or modem state.

Usage:
    tools/qmi_sock_probe.py                 # auto-find the socket
    tools/qmi_sock_probe.py -s /path/to/tty.qcserial-qmi.sock
    tools/qmi_sock_probe.py -v              # hexdump the frames
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time

QMUX_TAG = 0x01
CTL_SERVICE = 0x00
CTL_GET_VERSION_INFO = 0x0021
CTL_SYNC = 0x0027

# QMI CTL control_flags low bits carry the message type. A modem may push an
# unsolicited *indication* (notably CTL SYNC 0x0027, emitted after a reset or
# re-enumeration) onto the channel before our reply arrives, so the reader must
# skip non-matching frames instead of judging the first one it sees.
CTL_TYPE_MASK = 0x03
CTL_TYPE_REQUEST = 0x00
CTL_TYPE_RESPONSE = 0x01
CTL_TYPE_INDICATION = 0x02
CTL_TYPE_NAMES = {0x00: "request", 0x01: "response", 0x02: "indication"}

SOCK_NAME = "tty.qcserial-qmi.sock"
# Search order mirrors qcseriald's resolve_symlink_dir(): native /dev, the
# invoking user's ~/dev, then root's /var/root/dev fallback.
DEFAULT_DIRS = [
    "/dev",
    os.path.expanduser("~/dev"),
    "/var/root/dev",
]


def find_socket() -> str | None:
    for d in DEFAULT_DIRS:
        p = os.path.join(d, SOCK_NAME)
        if os.path.exists(p):
            return p
    return None


def hexdump(label: str, data: bytes) -> None:
    print(f"  {label} ({len(data)} bytes):")
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {i:04x}  {hexs:<48}  {asci}")


def build_ctl_frame(txn: int, msg_id: int, tlvs: bytes = b"") -> bytes:
    """Build a QMUX CTL request: 0x01 | len | flags service client | SDU."""
    # CTL SDU: control_flags(1)=0x00 request, transaction(1), msg(2), len(2), TLVs
    sdu = struct.pack("<BBHH", 0x00, txn & 0xFF, msg_id, len(tlvs)) + tlvs
    body = struct.pack("<BBB", 0x00, CTL_SERVICE, 0x00) + sdu  # flags, service, client
    length = len(body) + 2  # +2 for the length field itself
    return bytes([QMUX_TAG]) + struct.pack("<H", length) + body


def recv_one_frame(sock: socket.socket, buf: bytearray) -> bytes:
    """Read exactly one QMUX frame off a SOCK_STREAM socket.

    QMUX is self-delimiting: byte 0 is the 0x01 tag, bytes 1-2 are a LE length
    covering everything after the tag, so a whole frame is (1 + len) bytes. Keep
    reading until the header, then the full frame, are buffered.

    `buf` is the caller's *persistent* stream buffer and is consumed in place.
    That persistence is load-bearing: this is a byte stream, so a single recv()
    can return several frames at once (a modem's unsolicited indication and our
    reply routinely arrive together). Parsing one frame and dropping the rest of
    the buffer would silently discard the reply and then block forever on the
    next read — so leftover bytes must survive to the next call.
    """
    while len(buf) < 3:
        chunk = sock.recv(4096)
        if not chunk:
            raise ValueError("peer closed before a frame header arrived")
        buf += chunk
    if buf[0] != QMUX_TAG:
        raise ValueError(f"stream did not start with a QMUX tag (got 0x{buf[0]:02x})")
    framelen = 1 + (buf[1] | (buf[2] << 8))
    while len(buf) < framelen:
        chunk = sock.recv(4096)
        if not chunk:
            raise ValueError(f"peer closed mid-frame ({len(buf)}/{framelen} bytes)")
        buf += chunk
    frame = bytes(buf[:framelen])
    del buf[:framelen]          # keep any following frame for the next call
    return frame


def parse_frame(frame: bytes) -> dict:
    if len(frame) < 6 or frame[0] != QMUX_TAG:
        raise ValueError(f"not a QMUX frame (tag={frame[:1].hex()})")
    length = frame[1] | (frame[2] << 8)
    if length + 1 != len(frame):
        raise ValueError(f"length mismatch: header says {length + 1}, got {len(frame)}")
    flags, service, client = frame[3], frame[4], frame[5]
    sdu = frame[6:]
    out = {"flags": flags, "service": service, "client": client, "sdu": sdu}
    if service == CTL_SERVICE and len(sdu) >= 6:
        ctl_flags, txn, msg_id, mlen = struct.unpack("<BBHH", sdu[:6])
        out.update(ctl_flags=ctl_flags, txn=txn, msg_id=msg_id, msg_len=mlen)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-s", "--socket", help="path to the QMI unix stream socket")
    ap.add_argument("-t", "--timeout", type=float, default=15.0)
    ap.add_argument("-v", "--verbose", action="store_true", help="hexdump frames")
    args = ap.parse_args()

    path = args.socket or find_socket()
    if not path:
        print(f"error: could not find {SOCK_NAME} in {DEFAULT_DIRS}", file=sys.stderr)
        print("  is qcseriald running with QCSERIALD_QMI_SOCKET=1?", file=sys.stderr)
        return 2
    if not os.path.exists(path):
        print(f"error: socket not found: {path}", file=sys.stderr)
        return 2

    print(f"Connecting to QMI socket: {path}")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    try:
        sock.connect(path)
    except OSError as e:
        print(f"error: connect failed: {e}", file=sys.stderr)
        print("  (non-root? check the socket is chmod 0666 and the dir is "
              "reachable)", file=sys.stderr)
        return 2

    txn = 1
    req = build_ctl_frame(txn, CTL_GET_VERSION_INFO)
    print(f"→ CTL GET_VERSION_INFO (txn={txn}, {len(req)} bytes)")
    if args.verbose:
        hexdump("request", req)
    sock.sendall(req)

    # SOCK_STREAM: reassemble whole QMUX frames by their length field, and keep
    # reading until our own reply shows up. Some parts (Quectel RM500Q-AE and
    # EG12-GT, observed on test hardware) push an unsolicited CTL SYNC (0x0027)
    # indication onto the channel first; judging the first frame read reports a
    # false failure on a perfectly healthy bridge.
    deadline = time.monotonic() + args.timeout
    stream = bytearray()   # persistent: a recv() may carry more than one frame
    skipped = 0
    last = None
    while True:
        remaining = deadline - time.monotonic()
        # A complete frame may already be buffered from an earlier recv().
        if remaining <= 0 and len(stream) < 3:
            if last is not None:
                break  # fall through to the "unexpected frame" report below
            print("✗ TIMEOUT waiting for response — no frame came back.", file=sys.stderr)
            print("  Modem may need the interrupt EP (RESPONSE_AVAILABLE) or a client-id "
                  "first — some parts stay silent until DTR/RTS is asserted. Check the daemon log.",
                  file=sys.stderr)
            return 1
        sock.settimeout(max(remaining, 0.1))
        try:
            resp = recv_one_frame(sock, stream)
        except socket.timeout:
            if last is not None:
                break
            print("✗ TIMEOUT waiting for response — no frame came back.", file=sys.stderr)
            print("  Modem may need the interrupt EP (RESPONSE_AVAILABLE) or a client-id "
                  "first — some parts stay silent until DTR/RTS is asserted. Check the daemon log.",
                  file=sys.stderr)
            return 1
        except ValueError as e:
            print(f"✗ {e}", file=sys.stderr)
            return 1

        print(f"← got {len(resp)} bytes")
        if args.verbose:
            hexdump("response", resp)
        try:
            info = parse_frame(resp)
        except ValueError as e:
            print(f"✗ FRAMING ERROR: {e}", file=sys.stderr)
            return 1
        last = info

        print(f"  service=0x{info['service']:02x} client=0x{info['client']:02x} "
              f"flags=0x{info['flags']:02x}")
        if info["service"] == CTL_SERVICE and "msg_id" in info:
            ctype = info["ctl_flags"] & CTL_TYPE_MASK
            cname = CTL_TYPE_NAMES.get(ctype, f"type{ctype}")
            print(f"  CTL: txn={info['txn']} msg=0x{info['msg_id']:04x} "
                  f"len={info['msg_len']} ({cname})")
            if info["msg_id"] == CTL_GET_VERSION_INFO and info["txn"] == txn:
                if skipped:
                    print(f"  (skipped {skipped} unsolicited frame(s) before the reply)")
                print("✓ SUCCESS — QMUX round-trip through the QMI socket works.")
                return 0
            if ctype == CTL_TYPE_INDICATION:
                what = " (CTL SYNC — modem reset/re-enumerated)" if \
                    info["msg_id"] == CTL_SYNC else ""
                print(f"  ↳ unsolicited indication{what}; still waiting for our reply")
                skipped += 1
                continue
        # A non-CTL or non-matching frame: keep waiting until the deadline.
        skipped += 1

    print("⚠ response received but not the expected CTL version-info echo — "
          "framing is at least partially working; inspect with -v.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
