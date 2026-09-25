"""
Zombie Certificate Scanner Module for CertMate
================================================
Checks if domains inside active certificates still resolve in DNS
or respond to HTTP/HTTPS probes.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3

logger = logging.getLogger(__name__)

# Suppress insecure request warnings from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ZombieScanner:
    def __init__(self, timeout: float = 5.0, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers

    def check_domain(self, domain: str, port: int | None = None,
                     probe_host: str | None = None) -> str:
        """
        Check the status of a single domain.
        Returns: 'alive', 'suspect', 'zombie', or 'unverifiable'.

        ``probe_host`` is the name to actually contact, for a domain that
        cannot be probed as itself. That is the wildcard case: `*.example.com`
        used to be stripped to `example.com` and probed there, but a wildcard
        does not cover its own apex (RFC 6125), so the apex is frequently a
        name that resolves to nothing or serves nothing while every host the
        certificate protects is up. The scanner then reported `zombie`, which
        is its word for "delete this".

        Without a probe host a wildcard is `unverifiable` — not `alive`, not
        `zombie`. The deployment-status probe made the same mistake and had it
        fixed in #207/#381; it now refuses to guess in exactly this way, and
        this is the same refusal with the same word.
        """
        if not domain:
            return 'zombie'

        target = probe_host or domain
        if target.startswith('*.'):
            # A wildcard with nothing to stand in for it. Stripping the `*.`
            # would probe the one name the certificate is guaranteed NOT to
            # cover.
            logger.info(
                "Cannot probe %s as itself: a wildcard does not cover its "
                "apex. Set deployment_host to a name it covers.", domain)
            return 'unverifiable'

        if not target:
            return 'zombie'

        # 1. Passive DNS check
        try:
            socket.getaddrinfo(target, None)
        except (socket.gaierror, socket.herror, Exception) as e:
            logger.debug("DNS resolution failed for %s (target: %s): %s", domain, target, e)
            return 'zombie'

        # 2. Active HTTPS probe (use deployment_port if configured)
        if port:
            https_url = f"https://{target}:{port}"
            http_url = f"http://{target}:{port}"
        else:
            https_url = f"https://{target}"
            http_url = f"http://{target}"

        try:
            requests.head(
                https_url,
                timeout=self.timeout,
                headers={"User-Agent": "CertMate-ZombieScanner/1.0"}
            )
            return 'alive'
        except requests.exceptions.SSLError as e:
            logger.debug("HTTPS probe returned SSL error for %s (target: %s) - host is alive: %s", domain, target, e)
            return 'alive'
        except requests.RequestException as e:
            logger.debug("HTTPS probe failed for %s (target: %s): %s", domain, target, e)
            try:
                requests.head(
                    http_url,
                    timeout=self.timeout,
                    headers={"User-Agent": "CertMate-ZombieScanner/1.0"}
                )
                return 'alive'
            except requests.RequestException:
                pass
            return 'suspect'

    def scan_certificate(self, cert_info: dict) -> dict:
        """
        Scan all domains of a single certificate.
        Returns certificate details along with its status.
        """
        domain = cert_info.get('domain')
        san_domains = cert_info.get('san_domains') or []
        port = cert_info.get('deployment_port')
        # Read the same field the deployment-status probe reads, so the two
        # answer "which host stands in for this wildcard" the same way. It was
        # not read here at all, which is the whole defect: `deployment_port`
        # was honoured and `deployment_host` ignored.
        probe_host = cert_info.get('deployment_host') or None

        # Collect all unique domains to scan
        unique_domains = list(set([domain] + list(san_domains)))
        unique_domains = [d for d in unique_domains if d]

        domain_statuses = {}
        for d in unique_domains:
            # The probe host stands in for the wildcard, not for the concrete
            # SANs: those are probe-able as themselves and already are.
            stand_in = probe_host if d.startswith('*.') else None
            domain_statuses[d] = self.check_domain(d, port=port,
                                                  probe_host=stand_in)

        # Determine overall certificate status
        # alive:        at least one name answered
        # zombie:       every name we could ask about said nothing is there
        # unverifiable: nothing could be asked at all
        # suspect:      otherwise (some resolved but failed HTTP, none alive)
        statuses = list(domain_statuses.values())
        answerable = [s for s in statuses if s != 'unverifiable']
        if not statuses:
            overall_status = 'zombie'
        elif 'alive' in statuses:
            overall_status = 'alive'
        elif not answerable:
            # Every name was a wildcard with no stand-in. Reporting `zombie`
            # here is what deleted live estates on paper: nothing was asked,
            # so nothing is known.
            overall_status = 'unverifiable'
        elif all(s == 'zombie' for s in answerable):
            overall_status = 'zombie'
        else:
            overall_status = 'suspect'

        result = {
            'domain': domain,
            'status': overall_status,
            'domains': domain_statuses
        }
        if overall_status == 'unverifiable':
            apex = (domain or '')[2:] if (domain or '').startswith('*.') else domain
            result['reason'] = (
                f"Wildcard certificate {domain} cannot be checked "
                f"automatically: a wildcard does not cover its apex "
                f"({apex}), so probing {apex} would ask about the wrong "
                f"host. Set deployment_host to a name this wildcard covers "
                f"(for example www.{apex}) to enable the check: "
                f"Settings → Probe in the UI, or deployment_host via "
                f"PATCH /api/certificates/{domain}.")
        return result

    def scan_certificates(self, certs: list) -> dict:
        """
        Scan a list of certificate info dictionaries in parallel.
        """
        results = []
        total = len(certs)
        alive_count = 0
        suspect_count = 0
        zombie_count = 0
        unverifiable_count = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_cert = {executor.submit(self.scan_certificate, cert): cert for cert in certs}
            for future in as_completed(future_to_cert):
                try:
                    res = future.result()
                    results.append(res)
                    status = res['status']
                    if status == 'alive':
                        alive_count += 1
                    elif status == 'suspect':
                        suspect_count += 1
                    elif status == 'unverifiable':
                        # Counted apart rather than folded into `zombie`: a
                        # caller that adds the numbers up to decide what to
                        # delete must not be handed "we could not ask" as
                        # "nothing is there".
                        unverifiable_count += 1
                    else:
                        zombie_count += 1
                except Exception as e:
                    # A scan that crashed knows nothing about the certificate.
                    # This said `zombie`, which is the same mistake as the
                    # wildcard one this change is about: the scanner's own
                    # failure reported as a finding about the estate.
                    cert = future_to_cert[future]
                    logger.error("Error scanning certificate %s: %s", cert.get('domain'), e)
                    results.append({
                        'domain': cert.get('domain'),
                        'status': 'unverifiable',
                        'domains': {cert.get('domain'): 'unverifiable'},
                        'reason': 'the scan did not complete',
                        'error': str(e)
                    })
                    unverifiable_count += 1

        return {
            'summary': {
                'total': total,
                'alive': alive_count,
                'suspect': suspect_count,
                'zombie': zombie_count,
                'unverifiable': unverifiable_count
            },
            'results': results
        }
