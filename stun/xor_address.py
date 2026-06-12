"""XOR-MAPPED-ADDRESS encoding for Binding Success Responses."""

from __future__ import annotations

import ipaddress
import socket

from .constants import MAGIC_COOKIE


def encode_xor_mapped_address(ip: str, port: int, transaction_id: bytes) -> bytes:
    """Encode the RFC 5389 XOR-MAPPED-ADDRESS attribute value.

    For IPv4, the port is XORed with the most significant 16 bits of the magic
    cookie and the 32-bit address is XORed with the full magic cookie. IPv6 uses
    the magic cookie followed by the 96-bit transaction id as the XOR mask.
    """

    if not 0 <= port <= 65535:
        raise ValueError("port out of range")

    address = ipaddress.ip_address(ip)
    xport = port ^ (MAGIC_COOKIE >> 16)

    if address.version == 4:
        family = 0x01
        packed = socket.inet_pton(socket.AF_INET, ip)
        mask = MAGIC_COOKIE.to_bytes(4, "big")
    else:
        family = 0x02
        packed = socket.inet_pton(socket.AF_INET6, ip)
        mask = MAGIC_COOKIE.to_bytes(4, "big") + transaction_id

    xaddr = bytes(left ^ right for left, right in zip(packed, mask))
    return b"\x00" + family.to_bytes(1, "big") + xport.to_bytes(2, "big") + xaddr


def decode_xor_mapped_address(value: bytes, transaction_id: bytes) -> tuple[str, int]:
    """Decode an XOR-MAPPED-ADDRESS value, useful for tests and diagnostics."""

    if len(value) not in (8, 20):
        raise ValueError("invalid XOR-MAPPED-ADDRESS length")
    family = value[1]
    port = int.from_bytes(value[2:4], "big") ^ (MAGIC_COOKIE >> 16)
    if family == 0x01:
        mask = MAGIC_COOKIE.to_bytes(4, "big")
        raw = bytes(left ^ right for left, right in zip(value[4:], mask))
        return socket.inet_ntop(socket.AF_INET, raw), port
    if family == 0x02:
        mask = MAGIC_COOKIE.to_bytes(4, "big") + transaction_id
        raw = bytes(left ^ right for left, right in zip(value[4:], mask))
        return socket.inet_ntop(socket.AF_INET6, raw), port
    raise ValueError("unknown address family")
