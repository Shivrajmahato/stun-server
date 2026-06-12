"""Asyncio datagram protocol for stateless STUN handling."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from .constants import ATTR_MESSAGE_INTEGRITY, BINDING_REQUEST
from .fingerprint import verify_fingerprint
from .integrity import short_term_key, verify_message_integrity
from .parser import StunMessage, StunParseError, parse_message
from .response_builder import build_binding_response
from .server import Metrics, RateLimiter, ServerConfig


class StunDatagramProtocol(asyncio.DatagramProtocol):
    """Stateless UDP protocol implementation.

    No per-transaction state is stored. Each request is parsed, validated, and
    answered solely from the packet contents and observed UDP peer address.
    """

    def __init__(
        self,
        config: ServerConfig,
        metrics: Metrics,
        rate_limiter: RateLimiter,
        logger: logging.Logger,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.config = config
        self.metrics = metrics
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.clock = clock
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self.logger.info("stun_udp_listener_started", extra={"bind": f"{self.config.host}:{self.config.port}"})

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        started = self.clock()
        source_ip, source_port = addr
        self.metrics.note_ip(source_ip)
        self.metrics.requests_received += 1

        transaction_id = "-"
        request_type = "-"
        try:
            if not self.config.is_allowed(source_ip):
                raise StunParseError("source IP not in allowlist")
            if not self.rate_limiter.allow(source_ip):
                self.metrics.rate_limited += 1
                raise StunParseError("rate limit exceeded")

            message = parse_message(data)
            transaction_id = message.transaction_id_hex
            request_type = f"0x{message.message_type:04x}"
            self._validate_request(message)

            response = build_binding_response(
                message.transaction_id,
                source_ip,
                source_port,
                integrity_key=self._response_integrity_key(message),
                include_software=self.config.include_software,
                include_fingerprint=self.config.include_fingerprint,
            )
            if self.transport is None:
                raise RuntimeError("UDP transport not ready")
            self.transport.sendto(response, addr)
            self.metrics.responses_sent += 1
        except Exception as exc:
            self.metrics.invalid_packets += 1
            elapsed_ms = (self.clock() - started) * 1000
            self.logger.warning(
                "stun_request_rejected",
                extra={
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "transaction_id": transaction_id,
                    "request_type": request_type,
                    "response_time_ms": round(elapsed_ms, 3),
                    "error": str(exc),
                },
            )
            return

        elapsed_ms = (self.clock() - started) * 1000
        self.metrics.note_response_time(elapsed_ms)
        self.logger.info(
            "stun_binding_response_sent",
            extra={
                "source_ip": source_ip,
                "source_port": source_port,
                "transaction_id": transaction_id,
                "request_type": request_type,
                "response_time_ms": round(elapsed_ms, 3),
                "error": "",
            },
        )

    def error_received(self, exc: Exception) -> None:
        self.logger.error("stun_udp_error", extra={"error": str(exc)})

    def connection_lost(self, exc: Exception | None) -> None:
        self.logger.info("stun_udp_listener_stopped", extra={"error": "" if exc is None else str(exc)})

    def _validate_request(self, message: StunMessage) -> None:
        if message.message_type != BINDING_REQUEST:
            raise StunParseError(f"unsupported request type 0x{message.message_type:04x}")

        if self.config.require_fingerprint and not verify_fingerprint(message.raw):
            raise StunParseError("missing or invalid fingerprint")

        if self.config.integrity_password:
            mi_offset = self._message_integrity_offset(message.raw)
            if mi_offset is None:
                raise StunParseError("missing MESSAGE-INTEGRITY")
            key = short_term_key(self.config.integrity_password)
            if not verify_message_integrity(message.raw, key, mi_offset):
                raise StunParseError("invalid MESSAGE-INTEGRITY")

    def _response_integrity_key(self, message: StunMessage) -> bytes | None:
        if not self.config.integrity_password:
            return None
        if any(attribute.type == ATTR_MESSAGE_INTEGRITY for attribute in message.attributes):
            return short_term_key(self.config.integrity_password)
        return None

    @staticmethod
    def _message_integrity_offset(data: bytes) -> int | None:
        offset = 20
        end = len(data)
        while offset + 4 <= end:
            attr_type = int.from_bytes(data[offset : offset + 2], "big")
            attr_len = int.from_bytes(data[offset + 2 : offset + 4], "big")
            if attr_type == ATTR_MESSAGE_INTEGRITY:
                return offset
            offset += 4 + attr_len + ((4 - (attr_len % 4)) % 4)
        return None
