"""Tests for the inventory presentation helper (``modules/core/inventory_view.py``),
#471: days-until-expiry, at-a-glance status thresholds, issued/discovered
grouping, and the cumulative expiry forecast."""

from datetime import datetime, timedelta

import pytest

from modules.core.inventory_view import (
    build_inventory_view, days_until_expiry, expiry_status,
    EXPIRY_EXPIRED, EXPIRY_CRITICAL, EXPIRY_WARNING, EXPIRY_OK,
)

pytestmark = [pytest.mark.unit]

NOW = datetime(2026, 7, 28, 12, 0, 0)


def _iso(days_from_now):
    return (NOW + timedelta(days=days_from_now)).replace(microsecond=0).isoformat() + 'Z'


def _rec(**kw):
    base = {
        'fingerprint': 'fp', 'subject_cn': 'x', 'issuer_cn': 'CA',
        'not_after': _iso(60), 'source': 'probed', 'managed': False,
        'san_dns': [], 'key': {'type': 'RSA', 'size': 2048},
        'endpoints': [],
    }
    base.update(kw)
    return base


# --- primitives ------------------------------------------------------------ #

def test_days_until_expiry():
    assert days_until_expiry(_iso(30), NOW) == 30
    assert days_until_expiry(_iso(-5), NOW) == -5


def test_days_until_expiry_unparseable():
    assert days_until_expiry('not-a-date', NOW) is None
    assert days_until_expiry(None, NOW) is None


def test_days_until_expiry_offset_form_normalises_to_utc():
    # A tz-aware (+00:00) timestamp must normalise to UTC, not local time, so it
    # agrees with the 'Z' form and with datetime.utcnow()-based math.
    assert days_until_expiry('2026-08-27T12:00:00+00:00', NOW) == 30
    assert (days_until_expiry('2026-08-27T12:00:00Z', NOW)
            == days_until_expiry('2026-08-27T12:00:00+00:00', NOW))


@pytest.mark.parametrize('days,expected', [
    (-1, EXPIRY_EXPIRED),
    (0, EXPIRY_CRITICAL),
    (7, EXPIRY_CRITICAL),
    (8, EXPIRY_WARNING),
    (30, EXPIRY_WARNING),
    (31, EXPIRY_OK),
    (365, EXPIRY_OK),
])
def test_expiry_status_thresholds(days, expected):
    assert expiry_status(days) == expected


def test_expiry_status_unknown():
    assert expiry_status(None) == 'unknown'


# --- build_inventory_view -------------------------------------------------- #

def test_grouping_issued_vs_discovered():
    records = [
        _rec(fingerprint='a', managed=True, source='issued'),
        _rec(fingerprint='b', managed=False, source='ct-log'),
    ]
    view = build_inventory_view(records, NOW)
    groups = {c['fingerprint']: c['group'] for c in view['certificates']}
    assert groups['a'] == 'issued'
    assert groups['b'] == 'discovered'
    assert view['summary']['issued'] == 1
    assert view['summary']['discovered'] == 1
    assert view['summary']['total'] == 2


def test_per_record_expiry_fields():
    view = build_inventory_view([_rec(not_after=_iso(3))], NOW)
    item = view['certificates'][0]
    assert item['days_until_expiry'] == 3
    assert item['expiry_status'] == EXPIRY_CRITICAL


def test_by_source_breakdown():
    records = [
        _rec(fingerprint='a', source='probed'),
        _rec(fingerprint='b', source='probed'),
        _rec(fingerprint='c', source='ct-log'),
    ]
    summary = build_inventory_view(records, NOW)['summary']
    assert summary['by_source'] == {'probed': 2, 'ct-log': 1}


def test_forecast_buckets_are_cumulative():
    records = [
        _rec(fingerprint='exp', not_after=_iso(-1)),   # expired
        _rec(fingerprint='d5', not_after=_iso(5)),     # <=7, <=30, <=90
        _rec(fingerprint='d20', not_after=_iso(20)),   # <=30, <=90
        _rec(fingerprint='d60', not_after=_iso(60)),   # <=90
        _rec(fingerprint='d200', not_after=_iso(200)),  # none
        _rec(fingerprint='bad', not_after='nope'),     # unknown
    ]
    ex = build_inventory_view(records, NOW)['summary']['expiry']
    assert ex['expired'] == 1
    assert ex['7'] == 1
    assert ex['30'] == 2
    assert ex['90'] == 3
    assert ex['unknown'] == 1


def test_empty():
    view = build_inventory_view([], NOW)
    assert view['certificates'] == []
    assert view['summary']['total'] == 0
