#!/usr/bin/env python3
"""Per-module coverage floors for the HTTP layer and the core (#662).

The gated suite already has a project-wide `--cov-fail-under`. One number
cannot protect a layer: `modules/api/resources_ca.py` sat at 11% — 99 of its
111 statements never executed — while the project figure stayed comfortably
above its floor, because 3,800 well-covered statements elsewhere absorbed it.
That is the specific failure #662 describes: the network-exposed
request-handling and settings-mutation code was both the least covered and the
part whose confidence rested on paths the everyday gate does not run.

So each module gets its own floor, set from what it actually achieves. This is
a ratchet, not a target: raise a floor when coverage climbs, and never lower
one to make a build pass — a floor lowered to accommodate a regression is the
regression, recorded.

Two failure modes this deliberately does NOT allow:

* a module in the list that is missing from the report. Renaming or deleting a
  file would otherwise silently drop its floor, and the check would go on
  passing while covering less;
* a module in the report that is not in the list. A new HTTP module would
  otherwise arrive unguarded, which is exactly how resources_ca reached 11%.

Usage:  check_coverage_floors.py [coverage.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Floors are the measured value rounded down to a multiple of five, so ordinary
# churn does not trip the build while a real regression does.
FLOORS = {
    'modules/api/__init__.py': 100,
    'modules/api/client_certificates.py': 60,
    # 100 because it is 33 statements of pure logic with no I/O and no Flask
    # dependency beyond one after_request — there is no honest reason for any
    # of it to be unreached, and the mechanism is meant to be trustworthy on
    # the day it is first used, which is a day nobody will be testing it.
    'modules/api/deprecation.py': 100,
    'modules/api/models.py': 100,
    'modules/api/path_validation.py': 80,
    'modules/api/resource_context.py': 100,
    'modules/api/resources.py': 100,
    'modules/api/resources_backup.py': 65,
    'modules/api/resources_ca.py': 85,
    'modules/api/resources_cache.py': 80,
    'modules/api/resources_certificates.py': 50,
    'modules/api/resources_deployment.py': 80,
    'modules/api/resources_discovery.py': 75,
    'modules/api/resources_downloads.py': 75,
    # Raised from 70 after the closure was split into one function per check
    # and per collector: with each one callable directly, 84.4% was reached by
    # tests that no longer have to build an app to enter a branch. 80 rather
    # than 84 leaves room for a collector added without its own test to be a
    # review comment instead of a red gate.
    'modules/api/resources_health.py': 80,
    'modules/api/resources_inventory.py': 80,
    # Raised from 55 after covering the exception-to-status arms, which is
    # where this module's behaviour is: it is the entry point for every
    # create, renew and reissue, and a 500 where a 422 belongs sends an
    # operator looking inside CertMate for a problem in their DNS provider.
    'modules/api/resources_lifecycle.py': 77,
    'modules/api/resources_settings.py': 60,
    'modules/api/resources_storage.py': 70,
    'modules/api/tls_probe.py': 50,
    'modules/web/__init__.py': 100,
    'modules/web/auth_routes.py': 60,
    'modules/web/backup_cache_routes.py': 100,
    'modules/web/cert_routes.py': 55,
    'modules/web/misc_routes.py': 65,
    'modules/web/oidc_routes.py': 75,
    'modules/web/routes.py': 75,
    # Still the thinnest module in the project, and the next one to raise.
    # Left at 50 because nothing here added tests for it: measured at 50.8,
    # so raising the floor would lock in a number nobody earned.
    'modules/web/settings_routes.py': 50,
    'modules/web/ui_routes.py': 60,

    # modules/core/ — the layer this check did not watch.
    #
    # The floors above were added because one project-wide number could not
    # protect a layer: resources_ca.py sat at 11% while the project figure
    # stayed comfortably above its floor. The same argument applies with more
    # force one directory over, and it was not being made: modules/core holds
    # the issuance path, the storage backends, the settings store and the audit
    # chain, and nothing but the project-wide 75% stood behind any of it.
    #
    # What that allowed, measured rather than argued: storage_backends.py has
    # 1,202 statements of which 877 were covered. Losing every one of them —
    # a module whose tests are deleted or stop importing, which is exactly the
    # failure #651 describes — takes the project figure to 76.3%. Above the
    # floor. Green build, one of the largest modules in the product dark.
    #
    # Values are the measured coverage rounded DOWN to a multiple of five, and
    # down another five where that left less than a point of headroom, so
    # ordinary churn does not trip the build while a real regression does. They
    # come from the `unit` tier alone; the gated run also executes e2e and live
    # tests, so the real numbers are at or above these. Raise them as they
    # climb; never lower one to make a red build pass.
    'modules/core/__init__.py': 95,
    'modules/core/audit.py': 80,
    'modules/core/audit_chain.py': 85,
    'modules/core/audit_context.py': 90,
    'modules/core/audit_prune.py': 80,
    'modules/core/audit_signing.py': 85,
    'modules/core/audit_sink.py': 80,
    'modules/core/audit_verify.py': 75,
    'modules/core/auth.py': 85,
    'modules/core/ca_manager.py': 70,
    'modules/core/cache.py': 60,
    'modules/core/cert_adopt.py': 95,
    'modules/core/cert_discovery.py': 95,
    'modules/core/cert_inventory.py': 95,
    'modules/core/cert_jobs.py': 90,
    'modules/core/cert_probe.py': 80,
    'modules/core/cert_service.py': 90,
    'modules/core/certificates.py': 85,
    'modules/core/client_certificates.py': 75,
    'modules/core/constants.py': 80,
    'modules/core/crypto_report.py': 95,
    'modules/core/csr_handler.py': 80,
    'modules/core/csr_issuance.py': 95,
    'modules/core/ct_monitor.py': 90,
    'modules/core/deploy_targets.py': 90,
    'modules/core/deploy_window.py': 90,
    'modules/core/deployer.py': 85,
    'modules/core/digest.py': 85,
    'modules/core/dns_alias_hook.py': 65,
    # The one home for what a settings['domains'] entry is. High on
    # purpose: it is four small pure functions with no I/O, and every
    # other module now trusts them to decide what a domain entry means.
    'modules/core/domain_entries.py': 95,
    'modules/core/dns_providers.py': 85,
    'modules/core/dns_strategies.py': 80,
    'modules/core/dns_zone_discovery.py': 95,
    'modules/core/domain_paths.py': 85,
    'modules/core/events.py': 80,
    'modules/core/factory.py': 80,
    'modules/core/file_operations.py': 80,
    'modules/core/inventory_sources.py': 95,
    'modules/core/inventory_view.py': 95,
    'modules/core/issuance_readiness.py': 95,
    'modules/core/metrics.py': 70,
    'modules/core/notifier.py': 90,
    'modules/core/ocsp_crl.py': 85,
    'modules/core/oidc.py': 75,
    'modules/core/private_ca.py': 80,
    'modules/core/rate_limit.py': 70,
    'modules/core/secret_refs.py': 95,
    'modules/core/settings.py': 80,
    'modules/core/shell.py': 75,
    'modules/core/storage_backends.py': 70,
    'modules/core/structured_logging.py': 70,
    'modules/core/utils.py': 80,
    'modules/core/zombie.py': 80,
}

WATCHED_PREFIXES = ('modules/api/', 'modules/web/', 'modules/core/')


def main(argv: list[str]) -> int:
    report_path = Path(argv[1] if len(argv) > 1 else 'coverage.json')
    if not report_path.exists():
        print(f"coverage report not found: {report_path}", file=sys.stderr)
        print("run pytest with --cov-report=json:coverage.json first",
              file=sys.stderr)
        return 2

    report = json.loads(report_path.read_text(encoding='utf-8'))
    files = report.get('files', {})
    if not files:
        print("the coverage report lists no files at all — it was written by a "
              "run that measured nothing, so this check would pass vacuously",
              file=sys.stderr)
        return 2

    measured = {name: data['summary']['percent_covered']
                for name, data in files.items()
                if name.startswith(WATCHED_PREFIXES)}

    problems = []

    for name, floor in sorted(FLOORS.items()):
        if name not in measured:
            problems.append(
                f"{name}: has a floor of {floor}% but does not appear in the "
                f"coverage report. If it moved, move its floor; if it is gone, "
                f"delete the floor. Leaving it here means the floor is not "
                f"being enforced.")
            continue
        actual = measured[name]
        if actual + 1e-9 < floor:
            problems.append(
                f"{name}: {actual:.1f}% is below its floor of {floor}%. "
                f"Add tests, or say explicitly why the floor should move — "
                f"lowering it to go green records the regression instead of "
                f"fixing it.")

    for name in sorted(set(measured) - set(FLOORS)):
        problems.append(
            f"{name}: is a watched module with no coverage floor. Add one at "
            f"{int(measured[name] // 5 * 5)}% (its current {measured[name]:.1f}%) "
            f"so it cannot rot unnoticed.")

    if problems:
        print("Coverage floors not met:\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    lowest = min(measured.items(), key=lambda kv: kv[1])
    print(f"Coverage floors met for {len(measured)} watched modules "
          f"(lowest: {lowest[0]} at {lowest[1]:.1f}%).")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
