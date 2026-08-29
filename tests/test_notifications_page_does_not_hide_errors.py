"""The /notifications page must not paint 'all healthy' on an HTTP error.

loadNotifications did `r.ok ? r.json() : []`, turning a 401/403/500 into an
empty certificate list, which render() reads as 'nothing needs attention' — on
the one page whose job is to warn about expiring certs. It now rejects on an
HTTP error so the .catch shows the load failed (the pattern crypto_report.html
and inventory.js already use).
"""
import pathlib

import pytest

pytestmark = [pytest.mark.unit]

TEMPLATE = (pathlib.Path(__file__).resolve().parent.parent
            / 'templates' / 'notifications.html')


def test_an_http_error_rejects_instead_of_becoming_an_empty_list():
    src = TEMPLATE.read_text(encoding='utf-8')
    assert 'r.ok ? r.json() : []' not in src, \
        "an HTTP error must not silently become an empty certificate list"
    assert 'r.ok ? r.json() : Promise.reject(r.status)' in src


def test_the_catch_branch_reports_the_failure():
    src = TEMPLATE.read_text(encoding='utf-8')
    assert 'Could not load certificates.' in src


def test_the_catch_branch_clears_the_loading_state():
    """The failure path must reset the same busy/summary state render() does,
    or the page is left with aria-busy="true" and the summary stuck on
    'Loading…' (both stale to assistive tech)."""
    src = TEMPLATE.read_text(encoding='utf-8')
    catch = src.split('.catch(', 1)[1].split('});', 1)[0]
    assert "setAttribute('aria-busy', 'false')" in catch
    assert 'notifSummary' in catch
