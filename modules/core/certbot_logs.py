"""Masks the EAB credentials certbot wrote to its own logs before #1461.

certbot logs its command line at the start of every run, as a Python list:
``Arguments: [..., '--eab-kid', '<kid>', '--eab-hmac-key', '<key>', ...]``.
Until #1461 CertMate passed a CA account's EAB pair on that command line, so
every create or reissue with an EAB account left the key in
``<cert_dir>/<name>/logs/letsencrypt.log`` and in each rotated copy. New runs
read the pair from a config file whose contents certbot does not log; this
masks what earlier runs left. Backups never carried these files (``logs`` is
excluded), so the copies on disk are the only ones.

The pass runs once: a marker in the data directory records that it ran. Not in
the certificate directory, where every entry is read as a certificate.
"""
import logging
import os
import re
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

MARKER = '.certbot-logs-eab-masked'

# '--eab-kid', 'value'  /  "--eab-hmac-key", "value": the flag, then its value in either quote.
_FLAG_THEN_VALUE = re.compile(
    r"""(?P<flag>(?P<q1>['"])--eab-(?:kid|hmac-key)(?P=q1),\s*)(?P<q>['"])(?:(?!(?P=q)).)*(?P=q)""")
# '--eab-hmac-key=value'
_FLAG_EQUALS_VALUE = re.compile(r"""(?P<flag>(?P<q>['"])--eab-(?:kid|hmac-key)=)(?:(?!(?P=q)).)*""")


def mask(text: str) -> tuple[str, int]:
    """*text* with every EAB value certbot logged replaced by ``***``, and how many."""
    text, pairs = _FLAG_THEN_VALUE.subn(r'\g<flag>\g<q>***\g<q>', text)
    text, inline = _FLAG_EQUALS_VALUE.subn(r'\g<flag>***', text)
    return text, pairs + inline


def _mask_file(path: Path) -> int:
    """Mask one log in place, keeping its mode; the number of values masked."""
    raw = path.read_bytes()
    text = raw.decode('utf-8', errors='surrogateescape')
    masked, count = mask(text)
    if not count:
        return 0
    staged = path.with_name(path.name + '.masking')
    fd = os.open(str(staged), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(masked.encode('utf-8', errors='surrogateescape'))
    os.chmod(staged, path.stat().st_mode & 0o777)
    os.replace(staged, path)
    return count


def mask_eab_in_certbot_logs(cert_dir, data_dir) -> dict:
    """Mask every EAB value in ``<cert_dir>/*/logs/letsencrypt.log*``, once.

    Returns what it did, for the log line and for tests. Never raises: a log it
    cannot rewrite is named and left, and the marker is not written, so the
    next start tries again.
    """
    if cert_dir is None or data_dir is None:
        return _outcome(skipped=True)
    cert_dir = Path(cert_dir)
    marker = Path(data_dir) / MARKER
    if marker.exists() or not cert_dir.is_dir():
        return _outcome(skipped=True)
    files = masked_files = values = 0
    failed: list[str] = []
    for path in sorted(cert_dir.glob('*/logs/letsencrypt.log*')):
        if not path.is_file() or path.name.endswith('.masking'):
            continue
        files += 1
        try:
            count = _mask_file(path)
        except OSError as error:
            failed.append(str(path))
            logger.warning("Could not mask EAB credentials in %s: %s", path, error)
            continue
        if count:
            masked_files += 1
            values += count
    if values:
        logger.warning(
            "Masked %d EAB credential value(s) that certbot had logged in %d file(s) "
            "under %s (#1461). Consider rotating the EAB keys of the CA accounts involved.",
            values, masked_files, cert_dir)
    if not failed:
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text('EAB values in certbot logs masked (#1461)\n', encoding='utf-8')
        except OSError as error:
            logger.warning("Could not record that certbot logs were masked: %s", error)
    return _outcome(files=files, masked_files=masked_files, values=values, failed=failed)


def _outcome(*, skipped=False, files=0, masked_files=0, values=0, failed=()) -> dict:
    return {'skipped': skipped, 'files': files, 'masked_files': masked_files,
            'values': values, 'failed': list(failed)}


def mask_in_background(cert_dir, data_dir) -> threading.Thread:
    """Run the pass off the startup path: an estate can hold many rotated logs."""
    def run():
        try:
            mask_eab_in_certbot_logs(cert_dir, data_dir)
        except OSError as error:
            logger.error("Masking EAB credentials in certbot logs failed: %s", error)
    thread = threading.Thread(target=run, name='certmate-certbot-log-mask', daemon=True)
    thread.start()
    return thread
