"""Application entry point for the RFC 5389 STUN server."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from config import load_config
from stun.server import run_server


class ContextFormatter(logging.Formatter):
    """Logging formatter that tolerates missing structured fields."""

    def format(self, record: logging.LogRecord) -> str:
        for name in ("source_ip", "source_port", "transaction_id", "request_type", "response_time_ms", "error"):
            if not hasattr(record, name):
                setattr(record, name, "-")
        return super().format(record)


def configure_logging(level: str) -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        ContextFormatter(
            fmt=(
                "%(asctime)s %(levelname)s %(name)s %(message)s "
                "source_ip=%(source_ip)s source_port=%(source_port)s "
                "transaction_id=%(transaction_id)s request_type=%(request_type)s "
                "response_time_ms=%(response_time_ms)s error=%(error)s"
            ),
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    logger = logging.getLogger("stun-server")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    logger.propagate = False
    return logger


def main() -> int:
    parser = argparse.ArgumentParser(description="Production-ready RFC 5389 STUN server")
    parser.add_argument("--config", help="Path to TOML config file", default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    logger = configure_logging(config.log_level)
    try:
        asyncio.run(run_server(config, logger))
    except KeyboardInterrupt:
        logger.info("stun_server_interrupted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
