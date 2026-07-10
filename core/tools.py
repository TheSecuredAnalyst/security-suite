"""Utilities for external tool management and error handling."""

import shutil
import subprocess

from core.exceptions import ToolExecutionError, ToolNotFoundError
from core.logger import get_logger

logger = get_logger("core.tools")


class ToolManager:
    """Manage external tools and handle errors gracefully."""

    _tool_cache: dict[str, bool] = {}

    @staticmethod
    def find_tool(tool_name: str) -> str | None:
        """Find tool in system PATH.

        Args:
            tool_name: Name of the tool to find

        Returns:
            Path to tool if found, None otherwise
        """
        if tool_name in ToolManager._tool_cache:
            return tool_name if ToolManager._tool_cache[tool_name] else None

        path = shutil.which(tool_name)
        ToolManager._tool_cache[tool_name] = path is not None
        return path

    @staticmethod
    def check_tool(tool_name: str, raise_error: bool = True) -> bool:
        """Check if tool is available.

        Args:
            tool_name: Name of the tool to check
            raise_error: Raise ToolNotFoundError if tool not found

        Returns:
            True if tool is found, False otherwise

        Raises:
            ToolNotFoundError: If raise_error=True and tool not found
        """
        if ToolManager.find_tool(tool_name):
            return True

        if raise_error:
            raise ToolNotFoundError(tool_name)

        logger.warning(f"Tool '{tool_name}' not found")
        return False

    @staticmethod
    def run_command(
        command: list[str],
        tool_name: str = "external_tool",
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Run external command with error handling.

        Args:
            command: Command and arguments as list
            tool_name: Name of the tool for logging
            timeout: Command timeout in seconds

        Returns:
            Tuple of (stdout, stderr, returncode)

        Raises:
            ToolNotFoundError: If tool not found
            ToolExecutionError: If execution fails
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                logger.warning(
                    f"{tool_name} returned non-zero exit code: {result.returncode}"
                )
                if result.stderr:
                    logger.debug(f"{tool_name} stderr: {result.stderr}")

            return result.stdout, result.stderr, result.returncode

        except FileNotFoundError as e:
            logger.error(f"Tool '{tool_name}' not found in PATH")
            raise ToolNotFoundError(tool_name) from e

        except subprocess.TimeoutExpired as e:
            logger.error(f"{tool_name} execution timeout after {timeout}s")
            raise ToolExecutionError(tool_name, f"Timeout after {timeout}s") from e

        except Exception as e:
            logger.error(f"{tool_name} execution failed: {e}")
            raise ToolExecutionError(tool_name, str(e)) from e


def handle_tool_error(
    tool_name: str,
    fallback_value=None,
    log_level: str = "warning",
):
    """Decorator for graceful error handling of tool operations.

    Args:
        tool_name: Name of the tool
        fallback_value: Value to return if tool fails
        log_level: Log level for errors

    Example:
        @handle_tool_error("nmap", fallback_value=[])
        async def scan_ports(target):
            # nmap code
            pass
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except ToolNotFoundError as e:
                logger.log(
                    level=getattr(logger, log_level.upper()),
                    msg=f"Skipping {tool_name}: {e}"
                )
                return fallback_value
            except ToolExecutionError as e:
                logger.log(
                    level=getattr(logger, log_level.upper()),
                    msg=f"{tool_name} execution failed: {e.error}"
                )
                return fallback_value
            except Exception as e:
                logger.error(f"Unexpected error in {tool_name}: {e}")
                return fallback_value

        return wrapper

    return decorator
