"""Server runtime, configuration models, metrics, and protection utilities."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import signal
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 3478
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 8080
    log_level: str = "INFO"
    rate_limit_per_minute: int = 600
    allowlist: tuple[str, ...] = ()
    include_software: bool = True
    include_fingerprint: bool = True
    require_fingerprint: bool = False
    integrity_password: str | None = None
    _allow_networks: tuple[ipaddress._BaseNetwork, ...] = field(default=(), init=False, repr=False)

    def __post_init__(self) -> None:
        self._allow_networks = tuple(ipaddress.ip_network(item, strict=False) for item in self.allowlist if item)

    def is_allowed(self, source_ip: str) -> bool:
        if not self._allow_networks:
            return True
        ip = ipaddress.ip_address(source_ip)
        return any(ip in network for network in self._allow_networks)


@dataclass(slots=True)
class Metrics:
    requests_received: int = 0
    responses_sent: int = 0
    invalid_packets: int = 0
    rate_limited: int = 0
    total_response_time_ms: float = 0.0
    response_samples: int = 0
    active_ips: set[str] = field(default_factory=set)

    def note_ip(self, source_ip: str) -> None:
        self.active_ips.add(source_ip)

    def note_response_time(self, elapsed_ms: float) -> None:
        self.total_response_time_ms += elapsed_ms
        self.response_samples += 1

    @property
    def average_response_time_ms(self) -> float:
        if self.response_samples == 0:
            return 0.0
        return self.total_response_time_ms / self.response_samples

    def as_dict(self) -> dict[str, Any]:
        return {
            "requests_received": self.requests_received,
            "responses_sent": self.responses_sent,
            "invalid_packets": self.invalid_packets,
            "rate_limited": self.rate_limited,
            "average_response_time_ms": round(self.average_response_time_ms, 3),
            "active_ip_count": len(self.active_ips),
        }


class RateLimiter:
    """Sliding-window per-IP limiter for basic flood protection."""

    def __init__(self, limit_per_minute: int, window_seconds: int = 60) -> None:
        self.limit_per_minute = limit_per_minute
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, source_ip: str) -> bool:
        if self.limit_per_minute <= 0:
            return True
        now = time.monotonic()
        hits = self._hits[source_ip]
        cutoff = now - self.window_seconds
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= self.limit_per_minute:
            return False
        hits.append(now)
        return True


async def metrics_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, metrics: Metrics) -> None:
    """Serve a small HTTP/1.1 JSON metrics endpoint without external deps."""

    try:
        await reader.readuntil(b"\r\n\r\n")
    except Exception:
        pass
    body = (json.dumps(metrics.as_dict(), sort_keys=True) + "\n").encode("utf-8")
    headers = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
    )
    writer.write(headers + body)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def run_server(config: ServerConfig, logger: logging.Logger) -> None:
    """Start UDP STUN and HTTP metrics listeners until interrupted."""

    from .protocol import StunDatagramProtocol

    loop = asyncio.get_running_loop()
    metrics = Metrics()
    rate_limiter = RateLimiter(config.rate_limit_per_minute)
    transport, _ = await loop.create_datagram_endpoint(
        lambda: StunDatagramProtocol(config, metrics, rate_limiter, logger),
        local_addr=(config.host, config.port),
    )
    metrics_server = await asyncio.start_server(
        lambda reader, writer: metrics_handler(reader, writer, metrics),
        config.metrics_host,
        config.metrics_port,
    )

    stop_event = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            signal.signal(sig, lambda *_: stop_event.set())

    logger.info(
        "stun_server_ready",
        extra={
            "bind": f"{config.host}:{config.port}",
            "metrics": f"http://{config.metrics_host}:{config.metrics_port}/metrics",
        },
    )
    try:
        await stop_event.wait()
    finally:
        logger.info("stun_server_stopping")
        transport.close()
        metrics_server.close()
        await metrics_server.wait_closed()
