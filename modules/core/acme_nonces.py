"""Replay nonces for the ACME server (RFC 8555 section 6.5).

Every POST to the ACME server carries a nonce the server issued, and a nonce
is good for one request only: that is what makes a captured request useless
to replay. The store lives in memory, which is right for an instance that runs
one process (Dockerfile, certmate.service and the Helm chart all pin one): a
restart forgets every nonce, the next POST answers `badNonce` with a fresh one
in `Replay-Nonce`, and RFC 8555 clients retry on exactly that.

Nonces are 128 random bits, base64url without padding, the form the `nonce`
header field takes once josepy has decoded and re-encoded it.
"""
import os
import threading
import time
from collections import OrderedDict

from josepy import b64

DEFAULT_TTL_SECONDS = 3600
DEFAULT_CAPACITY = 10000


class NonceStore:
    """Issue nonces and accept each one once, within its lifetime."""

    def __init__(self, ttl_seconds=DEFAULT_TTL_SECONDS, capacity=DEFAULT_CAPACITY, clock=time.monotonic):
        self._ttl = ttl_seconds
        self._capacity = capacity
        self._clock = clock
        self._issued = OrderedDict()  # nonce -> expiry, oldest first
        self._lock = threading.Lock()

    def issue(self):
        nonce = b64.b64encode(os.urandom(16)).decode('ascii')
        now = self._clock()
        with self._lock:
            self._forget_expired(now)
            while len(self._issued) >= self._capacity:
                self._issued.popitem(last=False)
            self._issued[nonce] = now + self._ttl
        return nonce

    def consume(self, nonce):
        """True once for a nonce this store issued and that has not expired."""
        if not isinstance(nonce, str):
            return False
        with self._lock:
            expiry = self._issued.pop(nonce, None)
        return expiry is not None and expiry > self._clock()

    def __len__(self):
        with self._lock:
            return len(self._issued)

    def _forget_expired(self, now):
        while self._issued:
            nonce, expiry = next(iter(self._issued.items()))
            if expiry > now:
                break
            del self._issued[nonce]
