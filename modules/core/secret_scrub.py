"""Remove a secret, in every shape it can come back in, from text about to be recorded.

A deploy target hands a private key to a receiver and records what the receiver
answered. A receiver that echoes its input returns the key as it was sent, and
not always as PEM: as JSON-escaped PEM, as base64 (the Kubernetes Secret format
is exactly that), URL-encoded, or as one line of it. `sanitize_text` redacts PEM
blocks and base64-wrapped PEM; what it cannot know is the exact key that was
just sent. This knows it, so it removes that key's own pieces.

Two rules keep it honest:

* Scrub the WHOLE text, then shorten. Cutting an answer to its first few hundred
  characters and scrubbing afterwards leaves any fragment of the key that fell
  inside the cut, because a fragment matches none of the whole forms.
* Drop every line of the key's body (64 characters in a PEM) as well as the
  whole: a receiver that wraps or re-flows the text returns lines, not the PEM.
"""

import base64
import json
import urllib.parse

from .structured_logging import sanitize_text

REDACTED = '[REDACTED]'
KEY_REDACTED = '[KEY REDACTED]'

# Shorter than this and a "piece" would match ordinary words.
_MIN_PIECE = 24


def key_pieces(key_pem):
    """Every string that is, or is a slice of, *key_pem* in a form it travels in."""
    if isinstance(key_pem, str):
        key_pem = key_pem.encode()
    text = key_pem.decode('utf-8', 'replace')
    stripped = text.strip()
    lines = [line.strip() for line in stripped.splitlines()
             if line.strip() and not line.startswith('-----')]
    body = ''.join(lines)

    pieces = {text, stripped, json.dumps(text)[1:-1], json.dumps(stripped)[1:-1], body}
    # Three URL-encodings, because they differ on '/', which a base64 body is
    # full of: quote() keeps it, quote(safe='') and quote_plus() do not.
    for raw in (text, stripped, body):
        pieces.add(urllib.parse.quote(raw))
        pieces.add(urllib.parse.quote(raw, safe=''))
        pieces.add(urllib.parse.quote_plus(raw))
    for raw in (key_pem, key_pem.strip()):
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encode(raw).decode()
            pieces.update({encoded, encoded.rstrip('=')})
    for line in lines:
        pieces.add(line)
        pieces.add(urllib.parse.quote(line))
        pieces.add(urllib.parse.quote(line, safe=''))
    # Longest first, so a whole form is taken out before the lines inside it.
    return sorted((p for p in pieces if len(p) >= _MIN_PIECE), key=len, reverse=True)


def scrub(text, *, token=None, key_pem=None):
    """*text* with the bearer token, the key, and any PEM left in it, removed."""
    if not text:
        return text
    if token:
        text = text.replace(token, REDACTED)
    if key_pem:
        for piece in key_pieces(key_pem):
            text = text.replace(piece, KEY_REDACTED)
    return sanitize_text(text)
