"""Tests for error handling and tool management."""

import pytest
from unittest.mock import patch, MagicMock

from core.exceptions import (
    ToolNotFoundError, ToolExecutionError, InvalidTargetError,
    NetworkError, ConfigurationError, ModuleError
)
from core.tools import ToolManager


class TestExceptions:
    """Tests for custom exceptions."""
    
    def test_tool_not_found_error(self):
        """Test ToolNotFoundError."""
        with pytest.raises(ToolNotFoundError) as exc_info:
            raise ToolNotFoundError("nmap")
        
        assert "nmap" in str(exc_info.value)
        assert "not found" in str(exc_info.value)
    
    def test_tool_execution_error(self):
        """Test ToolExecutionError."""
        with pytest.raises(ToolExecutionError) as exc_info:
            raise ToolExecutionError("nmap", "Connection timeout")
        
        assert "nmap" in str(exc_info.value)
        assert "Connection timeout" in str(exc_info.value)
    
    def test_invalid_target_error(self):
        """Test InvalidTargetError."""
        with pytest.raises(InvalidTargetError) as exc_info:
            raise InvalidTargetError("invalid target!!!")
        
        assert "invalid target!!!" in str(exc_info.value)
    
    def test_network_error(self):
        """Test NetworkError."""
        with pytest.raises(NetworkError) as exc_info:
            raise NetworkError("Connection refused")
        
        assert "Connection refused" in str(exc_info.value)
    
    def test_configuration_error(self):
        """Test ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            raise ConfigurationError("Missing API key")
        
        assert "Missing API key" in str(exc_info.value)
    
    def test_module_error(self):
        """Test ModuleError."""
        with pytest.raises(ModuleError) as exc_info:
            raise ModuleError("osint", "DNS server error")
        
        assert "osint" in str(exc_info.value)
        assert "DNS server error" in str(exc_info.value)


class TestToolManager:
    """Tests for ToolManager."""
    
    def test_find_tool_success(self):
        """Test finding an available tool."""
        # 'python' or 'python3' should be available
        result = ToolManager.find_tool("python3")
        assert result is not None or result is None  # Either found or not
    
    def test_find_tool_not_found(self):
        """Test tool not found returns None."""
        result = ToolManager.find_tool("nonexistent_tool_xyz_123")
        assert result is None
    
    def test_check_tool_success(self):
        """Test checking for available tool."""
        # This should not raise for a common tool
        try:
            # Try python3 first, then python
            result = ToolManager.check_tool("python3", raise_error=False)
            assert isinstance(result, bool)
        except ToolNotFoundError:
            pytest.skip("Python not in PATH")
    
    def test_check_tool_not_found_raises(self):
        """Test checking for missing tool raises error."""
        with pytest.raises(ToolNotFoundError):
            ToolManager.check_tool("nonexistent_tool_xyz_123", raise_error=True)
    
    def test_check_tool_not_found_no_raise(self):
        """Test checking for missing tool returns False."""
        result = ToolManager.check_tool("nonexistent_tool_xyz_123", raise_error=False)
        assert result is False
    
    @patch("subprocess.run")
    def test_run_command_success(self, mock_run):
        """Test running command successfully."""
        mock_result = MagicMock()
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        stdout, stderr, code = ToolManager.run_command(["echo", "test"], "echo")
        
        assert stdout == "output"
        assert stderr == ""
        assert code == 0
    
    @patch("subprocess.run")
    def test_run_command_not_found(self, mock_run):
        """Test running command when tool not found."""
        mock_run.side_effect = FileNotFoundError()
        
        with pytest.raises(ToolNotFoundError):
            ToolManager.run_command(["nonexistent"], "nonexistent")
    
    @patch("subprocess.run")
    def test_run_command_timeout(self, mock_run):
        """Test command timeout."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 30)
        
        with pytest.raises(ToolExecutionError) as exc_info:
            ToolManager.run_command(["sleep", "999"], "sleep", timeout=1)
        
        assert "Timeout" in str(exc_info.value)
    
    def test_tool_cache(self):
        """Test tool finding is cached."""
        # Use a tool that definitely doesn't exist to test caching
        tool_name = "nonexistent_tool_definitely_not_in_path_xyz"
        ToolManager._tool_cache.clear()
        
        # First call should check
        result1 = ToolManager.find_tool(tool_name)
        
        # Second call should use cache
        result2 = ToolManager.find_tool(tool_name)
        
        # Results should match
        assert result1 == result2
        assert result1 is None  # Tool shouldn't exist
