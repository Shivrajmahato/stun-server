import asyncio
import logging

from stun.constants import ATTR_XOR_MAPPED_ADDRESS, BINDING_REQUEST, BINDING_RESPONSE, MAGIC_COOKIE
from stun.parser import parse_message
from stun.protocol import StunDatagramProtocol
from stun.server import Metrics, RateLimiter, ServerConfig
from stun.xor_address import decode_xor_mapped_address


class CaptureTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        self.sent.append((data, addr))


def request(txid: bytes = b"abcdefghijkl") -> bytes:
    return BINDING_REQUEST.to_bytes(2, "big") + b"\x00\x00" + MAGIC_COOKIE.to_bytes(4, "big") + txid


def test_binding_response_contains_xor_mapped_address() -> None:
    protocol = StunDatagramProtocol(ServerConfig(), Metrics(), RateLimiter(10), logging.getLogger("test"))
    transport = CaptureTransport()
    protocol.connection_made(transport)  # type: ignore[arg-type]
    protocol.datagram_received(request(), ("198.51.100.7", 55555))

    assert len(transport.sent) == 1
    response, addr = transport.sent[0]
    assert addr == ("198.51.100.7", 55555)
    parsed = parse_message(response)
    assert parsed.message_type == BINDING_RESPONSE
    xor_attr = next(attr for attr in parsed.attributes if attr.type == ATTR_XOR_MAPPED_ADDRESS)
    assert decode_xor_mapped_address(xor_attr.value, parsed.transaction_id) == ("198.51.100.7", 55555)


def test_rate_limit_rejects_flood() -> None:
    metrics = Metrics()
    protocol = StunDatagramProtocol(ServerConfig(rate_limit_per_minute=1), metrics, RateLimiter(1), logging.getLogger("test"))
    transport = CaptureTransport()
    protocol.connection_made(transport)  # type: ignore[arg-type]
    protocol.datagram_received(request(), ("198.51.100.8", 5000))
    protocol.datagram_received(request(b"mnopqrstuvwx"), ("198.51.100.8", 5000))

    assert len(transport.sent) == 1
    assert metrics.rate_limited == 1
    assert metrics.invalid_packets == 1


def test_metrics_handler_reports_counts() -> None:
    async def run() -> bytes:
        from stun.server import metrics_handler

        metrics = Metrics(requests_received=2, responses_sent=1, invalid_packets=1)
        server = await asyncio.start_server(lambda r, w: metrics_handler(r, w, metrics), "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        data = await reader.read()
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()
        return data

    data = asyncio.run(run())
    assert b'"requests_received": 2' in data
    assert b'"responses_sent": 1' in data
