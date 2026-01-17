"""
Structured JSON logging module for CertMate
============================================
Provides consistent, parseable JSON log output for observability and monitoring.

Features:
- JSON formatted logs for easy parsing (ELK, Loki, CloudWatch, etc.)
- Request ID tracking across log entries
- Performance timing
- Contextual fields (user, IP, domain, operation)
- Compatible with existing Python logging

Usage:
    from modules.core.structured_logging import get_logger, LogContext
    
    logger = get_logger(__name__)
    
    # Simple logging
    logger.info("Certificate created", domain="example.com", issuer="letsencrypt")
    
    # With context
    with LogContext(request_id="abc123", user="admin"):
        logger.info("Operation started")
        logger.info("Operation completed")  # Will include request_id and user
"""

import json
import logging
import time
import threading
import os
from datetime import datetime
from typing import Any, Dict, Optional
from contextvars import ContextVar
from functools import wraps

# Context variable for request-scoped data
_log_context: ContextVar[Dict[str, Any]] = ContextVar('log_context', default={})


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging"""
    
    # Fields to always include (in order)
    BASE_FIELDS = ['timestamp', 'level', 'logger', 'message']
    
    # Fields to exclude from extra (internal logging fields)
    EXCLUDE_FIELDS = {
        'name', 'msg', 'args', 'created', 'filename', 'funcName',
        'levelname', 'levelno', 'lineno', 'module', 'msecs',
        'pathname', 'process', 'processName', 'relativeCreated',
        'stack_info', 'exc_info', 'exc_text', 'thread', 'threadName',
        'taskName', 'message'
    }
    
    def __init__(self, include_hostname: bool = True, include_pid: bool = True):
        super().__init__()
        self.include_hostname = include_hostname
        self.include_pid = include_pid
        self._hostname = os.uname().nodename if include_hostname else None
        self._pid = os.getpid() if include_pid else None
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        
        # Build base log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname.lower(),
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        # Add source location for errors
        if record.levelno >= logging.WARNING:
            log_entry['source'] = {
                'file': record.filename,
                'line': record.lineno,
                'function': record.funcName
            }
        
        # Add hostname and PID
        if self._hostname:
            log_entry['host'] = self._hostname
        if self._pid:
            log_entry['pid'] = self._pid
        
        # Add context from ContextVar
        context = _log_context.get()
        if context:
            log_entry.update(context)
        
        # Add extra fields from record
        for key, value in record.__dict__.items():
            if key not in self.EXCLUDE_FIELDS and not key.startswith('_'):
                try:
                    # Ensure value is JSON serializable
                    json.dumps(value)
                    log_entry[key] = value
                except (TypeError, ValueError):
                    log_entry[key] = str(value)
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, default=str)


class StructuredLogger:
    """Logger wrapper that adds structured fields to log calls"""
    
    def __init__(self, logger: logging.Logger):
        self._logger = logger
    
    def _log(self, level: int, msg: str, **kwargs):
        """Internal log method with extra fields"""
        # Filter out None values
        extra = {k: v for k, v in kwargs.items() if v is not None}
        self._logger.log(level, msg, extra=extra)
    
    def debug(self, msg: str, **kwargs):
        self._log(logging.DEBUG, msg, **kwargs)
    
    def info(self, msg: str, **kwargs):
        self._log(logging.INFO, msg, **kwargs)
    
    def warning(self, msg: str, **kwargs):
        self._log(logging.WARNING, msg, **kwargs)
    
    def error(self, msg: str, **kwargs):
        self._log(logging.ERROR, msg, **kwargs)
    
    def critical(self, msg: str, **kwargs):
        self._log(logging.CRITICAL, msg, **kwargs)
    
    def exception(self, msg: str, **kwargs):
        """Log exception with traceback"""
        self._logger.exception(msg, extra=kwargs)


class LogContext:
    """Context manager for adding fields to all logs within a block"""
    
    def __init__(self, **kwargs):
        self.fields = kwargs
        self._token = None
    
    def __enter__(self):
        # Merge with existing context
        current = _log_context.get().copy()
        current.update(self.fields)
        self._token = _log_context.set(current)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        _log_context.reset(self._token)
        return False
    
    def add(self, **kwargs):
        """Add additional fields to context"""
        current = _log_context.get().copy()
        current.update(kwargs)
        _log_context.set(current)


def set_context(**kwargs):
    """Set context fields for current scope"""
    current = _log_context.get().copy()
    current.update(kwargs)
    _log_context.set(current)


def clear_context():
    """Clear all context fields"""
    _log_context.set({})


def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger by name"""
    return StructuredLogger(logging.getLogger(name))


def timed(logger: StructuredLogger, operation: str):
    """Decorator to log function execution time"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.perf_counter() - start) * 1000
                logger.info(
                    f"{operation} completed",
                    operation=operation,
                    duration_ms=round(duration_ms, 2),
                    status="success"
                )
                return result
            except Exception as e:
                duration_ms = (time.perf_counter() - start) * 1000
                logger.error(
                    f"{operation} failed",
                    operation=operation,
                    duration_ms=round(duration_ms, 2),
                    status="error",
                    error=str(e)
                )
                raise
        return wrapper
    return decorator


def configure_structured_logging(
    level: int = logging.INFO,
    json_output: bool = True,
    log_file: Optional[str] = None
):
    """
    Configure structured logging for the application.
    
    Args:
        level: Logging level (default: INFO)
        json_output: Use JSON format (default: True)
        log_file: Optional file path for log output
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    if json_output:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Reduce noise from third-party libraries
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)


# Flask request logging middleware helper
def get_request_context() -> Dict[str, Any]:
    """Extract context from Flask request for logging"""
    try:
        from flask import request, g
        
        context = {
            'request_id': getattr(g, 'request_id', None),
            'method': request.method,
            'path': request.path,
            'remote_addr': request.remote_addr,
            'user_agent': request.user_agent.string[:100] if request.user_agent else None,
        }
        
        # Add user if authenticated
        if hasattr(g, 'user'):
            context['user'] = g.user
        
        return {k: v for k, v in context.items() if v is not None}
    except RuntimeError:
        # Outside request context
        return {}


def log_request(logger: StructuredLogger):
    """Decorator to log Flask request/response"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            
            # Set request context
            ctx = get_request_context()
            with LogContext(**ctx):
                try:
                    result = func(*args, **kwargs)
                    duration_ms = (time.perf_counter() - start) * 1000
                    
                    # Log success
                    status_code = getattr(result, 'status_code', 200) if hasattr(result, 'status_code') else 200
                    logger.info(
                        "Request completed",
                        status_code=status_code,
                        duration_ms=round(duration_ms, 2)
                    )
                    return result
                    
                except Exception as e:
                    duration_ms = (time.perf_counter() - start) * 1000
                    logger.error(
                        "Request failed",
                        status_code=500,
                        duration_ms=round(duration_ms, 2),
                        error=str(e)
                    )
                    raise
        return wrapper
    return decorator


# Convenience: pre-configured CertMate loggers
def get_certmate_logger(component: str) -> StructuredLogger:
    """Get a logger for a CertMate component"""
    return get_logger(f"certmate.{component}")
