"""STUN attribute parsing and serialization helpers.

RFC 5389 attributes use a type-length-value layout. The length excludes the
4-byte attribute header and excludes any zero padding added to align the next
attribute to a 32-bit boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .constants import ATTRIBUTE_ALIGNMENT, ATTRIBUTE_HEADER_LENGTH


class AttributeParseError(ValueError):
    """Raised when an attribute block is malformed."""


@dataclass(frozen=True, slots=True)
class StunAttribute:
    """A parsed or to-be-serialized STUN attribute."""

    type: int
    value: bytes

    @property
    def length(self) -> int:
        return len(self.value)

    def encode(self) -> bytes:
        header = self.type.to_bytes(2, "big") + self.length.to_bytes(2, "big")
        return header + self.value + padding_for_length(self.length)


def padding_for_length(length: int) -> bytes:
    """Return zero padding required by RFC 5389 32-bit attribute alignment."""

    pad_len = (ATTRIBUTE_ALIGNMENT - (length % ATTRIBUTE_ALIGNMENT)) % ATTRIBUTE_ALIGNMENT
    return b"\x00" * pad_len


def iter_attributes(data: bytes) -> Iterable[StunAttribute]:
    """Parse a STUN attribute byte string into typed attributes.

    The caller passes exactly the attribute section identified by the message
    header length field. Any trailing partial header, short value, or non-zero
    impossible offset is treated as malformed input.
    """

    offset = 0
    total = len(data)
    while offset < total:
        if total - offset < ATTRIBUTE_HEADER_LENGTH:
            raise AttributeParseError("attribute header truncated")

        attr_type = int.from_bytes(data[offset : offset + 2], "big")
        attr_len = int.from_bytes(data[offset + 2 : offset + 4], "big")
        value_start = offset + ATTRIBUTE_HEADER_LENGTH
        value_end = value_start + attr_len
        if value_end > total:
            raise AttributeParseError("attribute value truncated")

        yield StunAttribute(attr_type, data[value_start:value_end])

        offset = value_end + len(padding_for_length(attr_len))

    if offset != total:
        raise AttributeParseError("attribute padding exceeds message length")


def encode_attributes(attributes: Iterable[StunAttribute]) -> bytes:
    return b"".join(attribute.encode() for attribute in attributes)
