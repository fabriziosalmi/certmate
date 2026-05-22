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

    def check_domain(self, domain: str) -> str:
        """
        Check the status of a single domain.
        Returns: 'alive', 'suspect', or 'zombie'.
        """
        if not domain:
            return 'zombie'
        
        # Clean wildcard
        target = domain
        if target.startswith('*.'):
            target = target[2:]
            
        if not target:
            return 'zombie'

        # 1. Passive DNS check
        try:
            socket.getaddrinfo(target, None)
        except (socket.gaierror, socket.herror, Exception) as e:
            logger.debug("DNS resolution failed for %s (target: %s): %s", domain, target, e)
            return 'zombie'

        # 2. Active HTTPS probe
        try:
            requests.head(
                f"https://{target}",
                timeout=self.timeout,
                headers={"User-Agent": "CertMate-ZombieScanner/1.0"}
            )
            # Any HTTP response means the host is alive
            return 'alive'
        except requests.exceptions.SSLError as e:
            # SSL error means the host responded to the TLS handshake, so it is alive!
            logger.debug("HTTPS probe returned SSL error for %s (target: %s) - host is alive: %s", domain, target, e)
            return 'alive'
        except requests.RequestException as e:
            logger.debug("HTTPS probe failed for %s (target: %s): %s", domain, target, e)
            # Try HTTP as fallback if HTTPS failed, just in case
            try:
                requests.head(
                    f"http://{target}",
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
        
        # Collect all unique domains to scan
        unique_domains = list(set([domain] + list(san_domains)))
        unique_domains = [d for d in unique_domains if d]
        
        domain_statuses = {}
        for d in unique_domains:
            domain_statuses[d] = self.check_domain(d)
            
        # Determine overall certificate status
        # alive: at least one domain is alive
        # zombie: all domains are zombie
        # suspect: otherwise (some domains resolved but failed HTTP, none alive)
        statuses = list(domain_statuses.values())
        if not statuses:
            overall_status = 'zombie'
        elif 'alive' in statuses:
            overall_status = 'alive'
        elif all(s == 'zombie' for s in statuses):
            overall_status = 'zombie'
        else:
            overall_status = 'suspect'
            
        return {
            'domain': domain,
            'status': overall_status,
            'domains': domain_statuses
        }

    def scan_certificates(self, certs: list) -> dict:
        """
        Scan a list of certificate info dictionaries in parallel.
        """
        results = []
        total = len(certs)
        alive_count = 0
        suspect_count = 0
        zombie_count = 0

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
                    else:
                        zombie_count += 1
                except Exception as e:
                    cert = future_to_cert[future]
                    logger.error("Error scanning certificate %s: %s", cert.get('domain'), e)
                    results.append({
                        'domain': cert.get('domain'),
                        'status': 'zombie',
                        'domains': {cert.get('domain'): 'zombie'},
                        'error': str(e)
                    })
                    zombie_count += 1

        return {
            'summary': {
                'total': total,
                'alive': alive_count,
                'suspect': suspect_count,
                'zombie': zombie_count
            },
            'results': results
        }
