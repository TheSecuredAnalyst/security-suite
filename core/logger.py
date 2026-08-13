"""Logging configuration for Security Suite."""

import logging
import re

from rich.console import Console
from rich.logging import RichHandler

# Shared console for rich output
console = Console()

# Control characters that let an attacker forge log lines or drive a terminal.
_LOG_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def scrub(value: object, max_length: int = 256) -> str:
    """Flatten an untrusted value so it cannot forge log entries (CWE-117).

    Targets, profiles, URLs and operator names all reach the log from outside.
    A value containing CRLF can otherwise inject a whole fake line — including a
    fake severity — into the log a responder later reads.

    Args:
        value: The untrusted value.
        max_length: Truncate beyond this many characters.

    Returns:
        A single-line, control-character-free string.
    """
    text = str(value).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    text = _LOG_CONTROL_CHARS.sub("", text)

    if len(text) > max_length:
        text = text[:max_length] + "…"

    return text


def get_logger(name: str, level: int | None = None) -> logging.Logger:
    """Get a configured logger instance.

    Args:
        name: Logger name (typically __name__)
        level: Optional log level override

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    if level is not None:
        logger.setLevel(level)
    elif not logger.level:
        logger.setLevel(logging.INFO)

    return logger


def setup_logging(debug: bool = False) -> None:
    """Setup global logging configuration.

    Args:
        debug: Enable debug logging if True
    """
    level = logging.DEBUG if debug else logging.INFO

    # Configure root logger
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[
            RichHandler(
                console=console,
                show_time=True,
                show_path=debug,
                rich_tracebacks=True,
            )
        ],
    )

    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
