"""
Server-Sent Events (SSE) event bus for CertMate.
Provides real-time updates to connected browser clients.
"""

import json
import logging
import queue
import time
import threading
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class EventBus:
    """Simple in-process event bus with SSE streaming support."""

    def __init__(self):
        self._subscribers = []
        self._listeners = []
        self._lock = threading.Lock()

    def add_listener(self, callback) -> None:
        """Register a callback invoked on every publish(). Signature: callback(event, data)."""
        with self._lock:
            self._listeners.append(callback)

    def subscribe(self) -> queue.Queue:
        """Create a new subscriber queue."""
        q = queue.Queue(maxsize=50)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """Remove a subscriber queue."""
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def publish(self, event: str, data: Optional[Dict[str, Any]] = None) -> None:
        """
        Publish an event to all subscribers.

        Args:
            event: Event type (e.g. certificate_created, certificate_renewed)
            data: Event payload
        """
        message = {
            'event': event,
            'data': data or {},
            'timestamp': time.time()
        }

        with self._lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(message)
                except queue.Full:
                    # Drop oldest message to make room
                    try:
                        q.get_nowait()
                        q.put_nowait(message)
                    except (queue.Empty, queue.Full):
                        dead.append(q)

            for q in dead:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass

        # Invoke listeners in background threads to avoid blocking
        for listener in self._listeners:
            try:
                threading.Thread(
                    target=listener,
                    args=(event, message.get('data', {})),
                    daemon=True
                ).start()
            except Exception as e:
                logger.debug(f"Event listener invocation failed: {e}")

    def stream(self, q: queue.Queue):
        """
        Generator that yields SSE-formatted events from a subscriber queue.
        Use with Flask's Response(stream_with_context(...)).
        """
        try:
            # Send initial keepalive
            yield f': connected\n\n'

            while True:
                try:
                    msg = q.get(timeout=30)
                    event_type = msg.get('event', 'message')
                    payload = json.dumps(msg.get('data', {}))
                    yield f'event: {event_type}\ndata: {payload}\n\n'
                except queue.Empty:
                    # Send keepalive comment to prevent connection timeout
                    yield f': keepalive\n\n'
        finally:
            self.unsubscribe(q)
