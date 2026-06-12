"""STUN response construction."""

from __future__ import annotations

from .attributes import StunAttribute, encode_attributes
from .constants import ATTR_SOFTWARE, ATTR_XOR_MAPPED_ADDRESS, BINDING_RESPONSE, HEADER_LENGTH, MAGIC_COOKIE
from .fingerprint import build_fingerprint_attribute
from .integrity import build_message_integrity_attribute
from .xor_address import encode_xor_mapped_address


SOFTWARE = b"python-rfc5389-stun/1.0"


def build_header(message_type: int, body_length: int, transaction_id: bytes) -> bytes:
    return (
        message_type.to_bytes(2, "big")
        + body_length.to_bytes(2, "big")
        + MAGIC_COOKIE.to_bytes(4, "big")
        + transaction_id
    )


def build_binding_response(
    transaction_id: bytes,
    source_ip: str,
    source_port: int,
    *,
    integrity_key: bytes | None = None,
    include_software: bool = True,
    include_fingerprint: bool = True,
) -> bytes:
    """Build a Binding Success Response.

    The response propagates the 96-bit transaction id from the request. The
    XOR-MAPPED-ADDRESS attribute tells the client the reflexive transport
    address observed by this server, which is the core RFC 5389 Binding flow.
    """

    attributes = [
        StunAttribute(ATTR_XOR_MAPPED_ADDRESS, encode_xor_mapped_address(source_ip, source_port, transaction_id)),
    ]
    if include_software:
        attributes.append(StunAttribute(ATTR_SOFTWARE, SOFTWARE))

    body = encode_attributes(attributes)
    message = build_header(BINDING_RESPONSE, len(body), transaction_id) + body

    if integrity_key is not None:
        mi_attr = build_message_integrity_attribute(message, integrity_key)
        body = body + mi_attr
        message = build_header(BINDING_RESPONSE, len(body), transaction_id) + body

    if include_fingerprint:
        final_body_length = len(body) + 8
        message_for_crc = build_header(BINDING_RESPONSE, final_body_length, transaction_id) + body
        fp_attr = build_fingerprint_attribute(message_for_crc)
        body = body + fp_attr
        message = build_header(BINDING_RESPONSE, len(body), transaction_id) + body

    assert len(message) == HEADER_LENGTH + int.from_bytes(message[2:4], "big")
    return message
