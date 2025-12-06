"""
Shell Execution Module for CertMate
Provides an interface for executing shell commands, enabling easier testing and mocking.
"""

import subprocess
import logging
from typing import List, Optional, Union, Dict, Any

logger = logging.getLogger(__name__)

class ShellExecutor:
    """Interface for executing shell commands"""
    
    def run(self, cmd: List[str], check: bool = False, capture_output: bool = True, 
            text: bool = True, timeout: Optional[int] = None, **kwargs) -> subprocess.CompletedProcess:
        """
        Run a shell command.
        
        Args:
            cmd: List of command arguments
            check: Whether to raise CalledProcessError if return code is non-zero
            capture_output: Whether to capture stdout/stderr
            text: Whether to decode output as text
            timeout: Timeout in seconds
            **kwargs: Additional arguments passed to subprocess.run
            
        Returns:
            subprocess.CompletedProcess instance
        """
        try:
            logger.debug(f"Executing command: {' '.join(cmd)}")
            return subprocess.run(
                cmd,
                check=check,
                capture_output=capture_output,
                text=text,
                timeout=timeout,
                **kwargs
            )
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timed out: {' '.join(cmd)}")
            raise
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise

class MockShellExecutor(ShellExecutor):
    """Mock implementation for testing"""
    
    def __init__(self):
        self.commands_executed = []
        self.responses = {}  # Map cmd_substring -> (returncode, stdout, stderr)
        self.response_queue = []  # Queue of responses for sequential calls
        self.call_count = 0
        
    def add_response(self, cmd_substring: str, returncode: int = 0, stdout: str = "", stderr: str = ""):
        """Add a canned response for a command containing the substring"""
        self.responses[cmd_substring] = (returncode, stdout, stderr)
    
    def set_next_result(self, returncode: int = 0, stdout: str = "", stderr: str = "", should_timeout: bool = False):
        """Queue a response for the next command execution"""
        self.response_queue.append({
            'returncode': returncode,
            'stdout': stdout,
            'stderr': stderr,
            'should_timeout': should_timeout
        })
        
    def run(self, cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
        cmd_str = " ".join(cmd)
        self.commands_executed.append(cmd_str)
        self.call_count += 1
        logger.info(f"Mock Executing: {cmd_str}")
        
        # Check for queued response first
        if self.response_queue:
            response = self.response_queue.pop(0)
            if response['should_timeout']:
                raise subprocess.TimeoutExpired(cmd, kwargs.get('timeout', 0))
            return subprocess.CompletedProcess(
                cmd, 
                response['returncode'], 
                response['stdout'], 
                response['stderr']
            )
        
        # Look for canned response by substring
        for k, v in self.responses.items():
            if k in cmd_str:
                returncode, stdout, stderr = v
                return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)
                
        # Default success
        return subprocess.CompletedProcess(cmd, 0, "", "")
