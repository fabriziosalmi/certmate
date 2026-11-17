"""The inventory knows the certificates CertMate holds, without probing for them.

The inventory had a source for them, ``issued``, and nothing ever wrote it: a
certificate CertMate manages entered the inventory only when a discovery sweep
probed its host over the network, and discovery is opt-in. So an instance that
managed 14 certificates showed "Managed 0, Total 0" (UX audit, 2026-11-17).
Decided the same day: the inventory counts them.

Each certificate directory's served ``cert.pem`` is read from disk and recorded
as managed, linked to its name, with the source CertMate's own records give it
(``issued``, or ``imported`` for an upload not renewed yet). No endpoint is
recorded: nothing was observed being served, which is what discovery adds when
it runs. A renewal records the new certificate; the one it replaced stays in
the inventory as superseded, as a renewal seen by discovery already did.
"""
import logging
import sqlite3
import threading

from .cert_probe import parse_certificate
from .constants import iter_cert_domain_dirs

logger = logging.getLogger(__name__)

#: The events after which a name's served certificate may be a new one.
_EVENTS = frozenset({'certificate_created', 'certificate_renewed'})


class HeldCertificatesInInventory:
    """Record the certificates *certificates* (a CertificateManager) holds in *inventory*."""

    def __init__(self, inventory, certificates):
        self.inventory = inventory
        self.certificates = certificates

    def _record(self, directory, held):
        try:
            described = parse_certificate((directory / 'cert.pem').read_bytes())['certificate']
        except (OSError, ValueError) as error:
            logger.debug("Inventory: %s has no readable certificate: %s", directory.name, error)
            return False
        self.inventory.record_certificate(
            described,
            source=held.get(described.get('fingerprint_sha256'), 'issued'),
            managed=True,
            managed_domain=directory.name,
        )
        return True

    def record_all(self):
        """Record every held certificate; how many were recorded."""
        held = self.certificates.held_certificate_sources()
        return sum(1 for directory in iter_cert_domain_dirs(self.certificates.cert_dir)
                   if self._record(directory, held))

    def record(self, name):
        """Record the certificate served for *name*; whether there was one."""
        directory = self.certificates.cert_dir / name
        if not (directory / 'cert.pem').is_file():
            return False
        return self._record(directory, self.certificates.held_certificate_sources())

    def on_event(self, event, data):
        """An event-bus listener: a created or renewed certificate is recorded."""
        name = (data or {}).get('domain') if event in _EVENTS else None
        if name:
            self.record(name)

    def record_all_in_background(self):
        """At startup, off the startup path: an estate can hold thousands."""
        def run():
            try:
                count = self.record_all()
            except (OSError, ValueError, sqlite3.Error) as error:
                logger.error("Inventory: could not record the certificates CertMate holds: %s", error)
                return
            logger.info("Inventory: %d certificate(s) CertMate holds recorded.", count)
        thread = threading.Thread(target=run, name='certmate-inventory-held', daemon=True)
        thread.start()
        return thread
