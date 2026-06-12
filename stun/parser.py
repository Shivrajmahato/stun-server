"""STUN header and attribute parser."""

from __future__ import annotations

from dataclasses import dataclass

from .attributes import StunAttribute, iter_attributes
from .constants import HEADER_LENGTH, MAGIC_COOKIE, MAX_STUN_DATAGRAM_SIZE, TRANSACTION_ID_LENGTH


class StunParseError(ValueError):
    """Raised when a UDP datagram is not a valid RFC 5389 STUN message."""


@dataclass(frozen=True, slots=True)
class StunMessage:
    message_type: int
    length: int
    magic_cookie: int
    transaction_id: bytes
    attributes: tuple[StunAttribute, ...]
    raw: bytes

    @property
    def transaction_id_hex(self) -> str:
        return self.transaction_id.hex()


def is_stun_message_type(message_type: int) -> bool:
    """RFC 5389 reserves the two most significant type bits as zero."""

    return (message_type & 0xC000) == 0


def parse_message(data: bytes) -> StunMessage:
    """Parse and validate a STUN message.

    Validation performed here is deliberately strict:
    * minimum 20 byte header
    * top two message-type bits are zero
    * message length is 32-bit aligned
    * datagram length exactly matches header length + body length
    * magic cookie is 0x2112A442
    * transaction id is present and propagated unchanged
    """

    if len(data) < HEADER_LENGTH:
        raise StunParseError("datagram shorter than STUN header")
    if len(data) > MAX_STUN_DATAGRAM_SIZE:
        raise StunParseError("datagram exceeds configured STUN size limit")

    message_type = int.from_bytes(data[0:2], "big")
    if not is_stun_message_type(message_type):
        raise StunParseError("message type top bits are not zero")

    length = int.from_bytes(data[2:4], "big")
    if length % 4 != 0:
        raise StunParseError("message length is not 32-bit aligned")
    if len(data) != HEADER_LENGTH + length:
        raise StunParseError("message length does not match datagram size")

    magic_cookie = int.from_bytes(data[4:8], "big")
    if magic_cookie != MAGIC_COOKIE:
        raise StunParseError("invalid magic cookie")

    transaction_id = data[8:20]
    if len(transaction_id) != TRANSACTION_ID_LENGTH:
        raise StunParseError("transaction id truncated")

    attributes = tuple(iter_attributes(data[HEADER_LENGTH:]))
    return StunMessage(message_type, length, magic_cookie, transaction_id, attributes, data)
