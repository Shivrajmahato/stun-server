"""RFC 5389 FINGERPRINT support."""

from __future__ import annotations

import binascii

from .constants import ATTR_FINGERPRINT, FINGERPRINT_LENGTH, FINGERPRINT_XOR


def calculate_fingerprint(message_with_fingerprint_length: bytes) -> int:
    """Calculate the RFC 5389 fingerprint value.

    The CRC-32 is computed over the complete STUN message up to, but excluding,
    the FINGERPRINT attribute itself. The message header length must already
    include the 8 bytes occupied by the FINGERPRINT attribute because that is
    the representation RFC 5389 requires for the calculation.
    """

    crc = binascii.crc32(message_with_fingerprint_length) & 0xFFFFFFFF
    return crc ^ FINGERPRINT_XOR


def build_fingerprint_attribute(message_with_fingerprint_length: bytes) -> bytes:
    value = calculate_fingerprint(message_with_fingerprint_length)
    return ATTR_FINGERPRINT.to_bytes(2, "big") + FINGERPRINT_LENGTH.to_bytes(2, "big") + value.to_bytes(4, "big")


def verify_fingerprint(full_message: bytes) -> bool:
    """Validate a final FINGERPRINT attribute on a STUN message."""

    if len(full_message) < 28:
        return False
    attr_type = int.from_bytes(full_message[-8:-6], "big")
    attr_len = int.from_bytes(full_message[-6:-4], "big")
    if attr_type != ATTR_FINGERPRINT or attr_len != FINGERPRINT_LENGTH:
        return False
    expected = int.from_bytes(full_message[-4:], "big")
    actual = calculate_fingerprint(full_message[:-8])
    return actual == expected
