"""
Rate limiting configuration for CertMate
Simple rate limiting configuration for API endpoints
"""

import logging
from typing import Dict, Optional
from functools import wraps
from flask import request
from collections import defaultdict
from time import time

logger = logging.getLogger(__name__)


class RateLimitConfig:
    """Configuration for API rate limiting."""

    # Default rate limits (requests per minute)
    DEFAULT_LIMITS = {
        'default': 100,  # 100 requests/minute default
        'certificate_create': 30,  # Creating certs is expensive
        'certificate_batch': 10,  # Batch operations are very expensive
        'certificate_list': 60,  # Listing is cheaper
        'certificate_revoke': 60,
        'certificate_renew': 30,
        'ocsp_status': 200,  # OCSP should be high
        'crl_download': 60,
    }

    def __init__(self, custom_limits: Optional[Dict[str, int]] = None):
        """
        Initialize Rate Limit Config.

        Args:
            custom_limits: Custom rate limit overrides
        """
        self.limits = dict(self.DEFAULT_LIMITS)
        if custom_limits:
            self.limits.update(custom_limits)

        logger.info(f"Rate limiting configured with {len(self.limits)} endpoint limits")

    def get_limit(self, endpoint: str) -> int:
        """
        Get rate limit for an endpoint.

        Args:
            endpoint: Endpoint name or path

        Returns:
            Rate limit (requests per minute)
        """
        # Try exact match first
        if endpoint in self.limits:
            return self.limits[endpoint]

        # Try prefix match
        for limit_key in self.limits:
            if endpoint.startswith(limit_key):
                return self.limits[limit_key]

        # Return default
        return self.limits.get('default', 100)


class SimpleRateLimiter:
    """Simple in-memory rate limiter (perfect for single-instance apps)."""

    # Maximum number of unique keys to track (prevents memory exhaustion under attack)
    MAX_KEYS = 10000

    def __init__(self, config: RateLimitConfig):
        """
        Initialize Rate Limiter.

        Args:
            config: RateLimitConfig instance
        """
        self.config = config
        self.requests = defaultdict(list)  # Track request times per IP
        self._last_cleanup = time()

    def is_allowed(self, identifier: str, endpoint: str) -> bool:
        """
        Check if request is allowed under rate limit.

        Args:
            identifier: IP address or user identifier
            endpoint: Endpoint being accessed

        Returns:
            True if request is allowed, False if rate limited
        """
        limit = self.config.get_limit(endpoint)
        current_time = time()
        window_start = current_time - 60  # 1 minute window

        # Periodic cleanup (every 5 minutes)
        if current_time - self._last_cleanup > 300:
            self.cleanup_old_entries()
            self._last_cleanup = current_time

        # Evict oldest entries if at capacity
        if len(self.requests) >= self.MAX_KEYS:
            self.cleanup_old_entries()
            # If still at capacity after cleanup, evict random entries
            if len(self.requests) >= self.MAX_KEYS:
                excess = len(self.requests) - self.MAX_KEYS + 100  # Free 100 slots
                for evict_key in list(self.requests.keys())[:excess]:
                    del self.requests[evict_key]

        # Get requests for this identifier
        key = f"{identifier}:{endpoint}"
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if req_time > window_start
        ]

        # Check if under limit
        if len(self.requests[key]) >= limit:
            logger.warning(f"Rate limit exceeded for {identifier} on {endpoint}")
            return False

        # Record this request
        self.requests[key].append(current_time)
        return True

    def cleanup_old_entries(self) -> None:
        """Clean up old request records (call periodically)."""
        try:
            current_time = time()
            window_start = current_time - 3600  # Keep 1 hour of data

            for key in list(self.requests.keys()):
                self.requests[key] = [
                    req_time for req_time in self.requests[key]
                    if req_time > window_start
                ]
                if not self.requests[key]:
                    del self.requests[key]

        except Exception as e:
            logger.error(f"Error cleaning up rate limit entries: {e}")


def rate_limit_decorator(limiter: SimpleRateLimiter, endpoint: str):
    """
    Decorator for rate limiting Flask endpoints.

    Args:
        limiter: SimpleRateLimiter instance
        endpoint: Endpoint identifier

    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Use remote_addr to prevent rate-limit bypass via spoofed headers.
            # Configure Werkzeug ProxyFix if behind a trusted reverse proxy.
            client_ip = request.remote_addr or '0.0.0.0'

            # Check rate limit
            if not limiter.is_allowed(client_ip, endpoint):
                logger.warning(
                    f"Rate limit exceeded: {client_ip} on {endpoint}"
                )
                return {
                    'error': 'Rate limit exceeded',
                    'message': 'Too many requests. Please try again later.',
                    'retry_after': 60
                }, 429

            return f(*args, **kwargs)

        return decorated_function

    return decorator
