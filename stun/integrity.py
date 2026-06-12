"""Optional RFC 5389 MESSAGE-INTEGRITY helpers."""

from __future__ import annotations

import hashlib
import hmac

from .constants import ATTR_MESSAGE_INTEGRITY, HEADER_LENGTH, MESSAGE_INTEGRITY_LENGTH


def short_term_key(password: str) -> bytes:
    """Return the short-term credential key used by HMAC-SHA1."""

    return password.encode("utf-8")


def long_term_key(username: str, realm: str, password: str) -> bytes:
    """Return the long-term credential key: MD5(username:realm:password)."""

    material = f"{username}:{realm}:{password}".encode("utf-8")
    return hashlib.md5(material).digest()


def calculate_message_integrity(message_with_integrity_length: bytes, key: bytes) -> bytes:
    """Calculate MESSAGE-INTEGRITY for a STUN message.

    RFC 5389 computes HMAC-SHA1 over the STUN message through the attribute
    immediately before MESSAGE-INTEGRITY, while the header length field is set
    as if the MESSAGE-INTEGRITY attribute and its 20 byte value are present.
    """

    return hmac.new(key, message_with_integrity_length, hashlib.sha1).digest()


def build_message_integrity_attribute(message_before_integrity: bytes, key: bytes) -> bytes:
    length = len(message_before_integrity) - HEADER_LENGTH + 24
    header = message_before_integrity[:2] + length.to_bytes(2, "big") + message_before_integrity[4:HEADER_LENGTH]
    adjusted = header + message_before_integrity[HEADER_LENGTH:]
    digest = calculate_message_integrity(adjusted, key)
    return ATTR_MESSAGE_INTEGRITY.to_bytes(2, "big") + MESSAGE_INTEGRITY_LENGTH.to_bytes(2, "big") + digest


def verify_message_integrity(full_message: bytes, key: bytes, attr_offset: int) -> bool:
    """Verify MESSAGE-INTEGRITY at an absolute message offset."""

    attr_end = attr_offset + 4 + MESSAGE_INTEGRITY_LENGTH
    if attr_end > len(full_message):
        return False
    supplied = full_message[attr_offset + 4 : attr_end]
    adjusted_len = attr_end - HEADER_LENGTH
    adjusted_header = full_message[:2] + adjusted_len.to_bytes(2, "big") + full_message[4:HEADER_LENGTH]
    signed_portion = adjusted_header + full_message[HEADER_LENGTH:attr_offset]
    expected = calculate_message_integrity(signed_portion, key)
    return hmac.compare_digest(supplied, expected)
