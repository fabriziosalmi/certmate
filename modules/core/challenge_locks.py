"""One DNS-01 validation at a time per challenge record (#854, step 2: #1147).

Issuance and renewal are serialised per certificate (the per-domain lock in
certificates.py), and up to CERTMATE_ISSUANCE_WORKERS (default 2) run at once.
Two different certificates can still answer their DNS-01 challenges at the
same record: `example.com` and `*.example.com` both write
`_acme-challenge.example.com`, and so do two certificates whose challenges are
delegated to one alias. Some DNS plugins write the record set as a whole:
certbot-dns-route53 keeps, per process, the values it added and UPSERTs the
set with only those, so a second certbot validating the same name replaces the
first one's value, and whichever cleanup runs last decides what is left. The
EdgeDNS alias hook did the same until #1144.

So the certbot run of an issuance or a renewal holds a lock per challenge
record it will write. Two certificates whose records do not overlap still run
in parallel. When they overlap, the second is refused the way the per-domain
lock refuses (DomainOperationInProgress, a 409 to an API caller), naming the
record, and is retried: the nightly sweep tries again the next night, and a
caller can retry when the first finishes.

The locks are per process, like the per-domain lock, for the same reason: the
image runs one worker (see `_get_domain_lock`).
"""
import threading
from contextlib import contextmanager


def challenge_record_names(domains, domain_alias=None, challenge_type=None):
    """The DNS records an issuance for `domains` will write, sorted.

    A wildcard is validated at its base name. With an alias (CNAME
    delegation), every name's challenge is answered at the alias, so there is
    one record. HTTP-01 and Sectigo's prevalidated authorizations write none.
    """
    if challenge_type in ('http-01', 'prevalidated'):
        return []
    if domain_alias:
        return [f'_acme-challenge.{domain_alias.strip(".").lower()}']
    names = set()
    for domain in domains or ():
        if not domain:
            continue
        base = domain[2:] if domain.startswith('*.') else domain
        names.add(f'_acme-challenge.{base.strip(".").lower()}')
    return sorted(names)


class ChallengeRecordBusy(RuntimeError):
    """Raised when another certbot run is validating at the same record."""


class ChallengeLocks:
    """A lock per challenge record name, taken in sorted order."""

    def __init__(self):
        self._locks = {}
        self._mutex = threading.Lock()

    def _lock(self, name):
        with self._mutex:
            return self._locks.setdefault(name, threading.Lock())

    @contextmanager
    def hold(self, names, timeout):
        """Hold every lock in `names` for the block, or raise ChallengeRecordBusy.

        Sorted acquisition, so two runs that need overlapping sets cannot each
        hold one and wait for the other. On a refusal, what was taken is
        released before raising."""
        taken = []
        try:
            for name in sorted(set(names)):
                lock = self._lock(name)
                if not lock.acquire(timeout=timeout):
                    raise ChallengeRecordBusy(name)
                taken.append(lock)
            yield
        finally:
            for lock in reversed(taken):
                lock.release()
