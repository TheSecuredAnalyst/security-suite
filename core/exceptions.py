"""Custom exceptions for Security Suite."""


class SecuritySuiteException(Exception):  # noqa: N818  # public API name, kept for compatibility
    """Base exception for Security Suite."""
    pass


class ToolNotFoundError(SecuritySuiteException):
    """Raised when an external tool is not found."""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        super().__init__(f"Tool '{tool_name}' not found. Please install it first.")


class ToolExecutionError(SecuritySuiteException):
    """Raised when a tool execution fails."""

    def __init__(self, tool_name: str, error: str):
        self.tool_name = tool_name
        self.error = error
        super().__init__(f"Execution of '{tool_name}' failed: {error}")


class InvalidTargetError(SecuritySuiteException):
    """Raised when target validation fails."""

    def __init__(self, target: str):
        self.target = target
        super().__init__(f"Invalid target: {target}")


class NetworkError(SecuritySuiteException):
    """Raised when network operations fail."""

    def __init__(self, message: str):
        super().__init__(f"Network error: {message}")


class ConfigurationError(SecuritySuiteException):
    """Raised when configuration is invalid."""

    def __init__(self, message: str):
        super().__init__(f"Configuration error: {message}")


class ModuleError(SecuritySuiteException):
    """Raised when module execution fails."""

    def __init__(self, module_name: str, error: str):
        self.module_name = module_name
        self.error = error
        super().__init__(f"Module '{module_name}' error: {error}")
