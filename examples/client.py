"""Minimal STUN Binding Request client for validation."""

from __future__ import annotations

import argparse
import os
import socket

from stun.constants import ATTR_XOR_MAPPED_ADDRESS, BINDING_REQUEST, MAGIC_COOKIE
from stun.parser import parse_message
from stun.xor_address import decode_xor_mapped_address


def build_request() -> bytes:
    transaction_id = os.urandom(12)
    return BINDING_REQUEST.to_bytes(2, "big") + b"\x00\x00" + MAGIC_COOKIE.to_bytes(4, "big") + transaction_id


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a STUN Binding Request")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=3478)
    args = parser.parse_args()

    packet = build_request()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(packet, (args.host, args.port))
        data, _ = sock.recvfrom(2048)

    response = parse_message(data)
    attr = next(attribute for attribute in response.attributes if attribute.type == ATTR_XOR_MAPPED_ADDRESS)
    ip, port = decode_xor_mapped_address(attr.value, response.transaction_id)
    print(f"Observed public address: {ip}:{port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
