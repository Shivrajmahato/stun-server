from stun.xor_address import decode_xor_mapped_address, encode_xor_mapped_address


def test_ipv4_xor_mapped_address_round_trip() -> None:
    txid = bytes.fromhex("00112233445566778899aabb")
    value = encode_xor_mapped_address("203.0.113.5", 54321, txid)
    assert value[1] == 0x01
    assert decode_xor_mapped_address(value, txid) == ("203.0.113.5", 54321)


def test_ipv6_xor_mapped_address_round_trip() -> None:
    txid = bytes.fromhex("00112233445566778899aabb")
    value = encode_xor_mapped_address("2001:db8::1", 3478, txid)
    decoded_ip, decoded_port = decode_xor_mapped_address(value, txid)
    assert decoded_ip == "2001:db8::1"
    assert decoded_port == 3478
