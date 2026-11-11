"""A certificate still issuing stays in the list until its job ends (#1426).

pollCertJob gave up after 150 attempts, about 5 minutes at 2 seconds, and deleted the
"Issuing" row of a job that was still running: issuance goes on in the background
executor, and a DNS propagation wait alone can be configured past 5 minutes. A reload
brought the row back. A failure that came after the row was gone was never shown, because
nothing else reports a failed create to the page.

It now polls for as long as the job is queued or running, every 2 seconds for the first
minute and then slower, up to every 10, and stops only on succeeded, failed, or a 404 for
a job the server no longer knows. These run the real function in node, with fetch and
setTimeout under the test's control.
"""
import json
import pathlib
import re
import shutil
import subprocess

import pytest

pytestmark = [pytest.mark.unit]

DASHBOARD = (pathlib.Path(__file__).resolve().parent.parent / 'static' / 'js' / 'dashboard.js').read_text()


def _function(name):
    found = re.search(r'\n    function ' + name + r'\(.*?\n    \}\n', DASHBOARD, re.S)
    assert found, f'{name} not found in dashboard.js'
    return found.group(0)


def _poll(answers):
    """Poll one job against *answers* (one per request: a status, 404, or 'network'), and
    report what the page did and the delays it waited."""
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not available')
    helpers = _function('pollDelay') if 'function pollDelay(' in DASHBOARD else ''
    script = (
        "var answers = " + json.dumps(answers) + ", asked = 0, delays = [], timers = [];\n"
        "var pendingJobs = {j: {domain: 'slow.example.com', kind: 'create', state: 'running'}};\n"
        "var pendingPollTimers = {}, API_HEADERS = {}, messages = [], reloads = 0, renders = 0;\n"
        "function setTimeout(fn, ms) { delays.push(ms); timers.push(fn); return timers.length; }\n"
        "function loadCertificates() { reloads++; } function renderPendingRows() { renders++; }\n"
        "function showMessage(text, kind) { messages.push([kind, text]); }\n"
        "function fetch() { var a = answers[Math.min(asked++, answers.length - 1)];\n"
        "  if (a === 'network') return Promise.reject(new Error('offline'));\n"
        "  if (a === 404) return Promise.resolve({status: 404});\n"
        "  return Promise.resolve({status: 200, json: function () {\n"
        "    return a === 'failed' ? {status: 'failed', error: 'DNS problem: NXDOMAIN'} : {status: a}; }}); }\n"
        + helpers + _function('pollCertJob')
        + "pollCertJob('j', '/api/certificates/jobs/j');\n"
        "(async function () { while (timers.length) { timers.shift()();\n"
        "  for (var i = 0; i < 5; i++) await new Promise(function (r) { setImmediate(r); }); }\n"
        "  console.log(JSON.stringify({job: pendingJobs.j || null, asked: asked, messages: messages,\n"
        "    reloads: reloads, delays: delays})); })();\n")
    result = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_a_job_still_running_after_five_minutes_keeps_its_row_and_its_failure_is_shown():
    out = _poll(['running'] * 200 + ['failed'])

    assert out['asked'] == 201, 'the page stopped asking while the job was running'
    assert out['job'] is not None and out['job']['state'] == 'failed'
    assert out['messages'] and 'NXDOMAIN' in out['messages'][-1][1]


def test_it_asks_slower_as_time_goes_on_but_keeps_asking():
    delays = _poll(['running'] * 60 + ['succeeded'])['delays']

    assert delays[1] == 2000
    assert max(delays) <= 10000
    assert delays[-1] > 2000


def test_a_job_the_server_no_longer_knows_ends_the_poll():
    out = _poll(['running', 404])

    assert out['job'] is None and out['reloads'] == 1 and out['asked'] == 2


def test_a_network_failure_does_not_end_the_poll():
    out = _poll(['network'] * 160 + ['succeeded'])

    assert out['asked'] == 161 and out['reloads'] == 1
