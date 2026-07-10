"""Logging configuration for Security Suite."""

import logging

from rich.console import Console
from rich.logging import RichHandler

# Shared console for rich output
console = Console()


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
