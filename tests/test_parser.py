from stun.attributes import StunAttribute
from stun.constants import ATTR_FINGERPRINT, BINDING_REQUEST, MAGIC_COOKIE
from stun.fingerprint import build_fingerprint_attribute, verify_fingerprint
from stun.parser import StunParseError, parse_message


def header(message_type: int, body: bytes, transaction_id: bytes = b"abcdefghijkl") -> bytes:
    return message_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + MAGIC_COOKIE.to_bytes(4, "big") + transaction_id


def test_parse_binding_request_extracts_transaction_id() -> None:
    packet = header(BINDING_REQUEST, b"")
    message = parse_message(packet)
    assert message.message_type == BINDING_REQUEST
    assert message.length == 0
    assert message.transaction_id == b"abcdefghijkl"


def test_rejects_invalid_magic_cookie() -> None:
    packet = BINDING_REQUEST.to_bytes(2, "big") + b"\x00\x00" + b"\x00\x00\x00\x00" + b"abcdefghijkl"
    try:
        parse_message(packet)
    except StunParseError as exc:
        assert "magic cookie" in str(exc)
    else:
        raise AssertionError("expected parse failure")


def test_rejects_mismatched_length() -> None:
    packet = BINDING_REQUEST.to_bytes(2, "big") + b"\x00\x04" + MAGIC_COOKIE.to_bytes(4, "big") + b"abcdefghijkl"
    try:
        parse_message(packet)
    except StunParseError as exc:
        assert "length" in str(exc)
    else:
        raise AssertionError("expected parse failure")


def test_attribute_parser_handles_padding() -> None:
    attr = StunAttribute(0x8022, b"abc").encode()
    message = parse_message(header(BINDING_REQUEST, attr) + attr)
    assert message.attributes[0].type == 0x8022
    assert message.attributes[0].value == b"abc"


def test_fingerprint_verification() -> None:
    message_for_crc = header(BINDING_REQUEST, b"\x00" * 8)
    fp = build_fingerprint_attribute(message_for_crc)
    packet = header(BINDING_REQUEST, fp) + fp
    assert int.from_bytes(packet[-8:-6], "big") == ATTR_FINGERPRINT
    assert verify_fingerprint(packet)
