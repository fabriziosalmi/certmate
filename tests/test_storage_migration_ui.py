"""The migration dialog must not guess a source from the target backend type."""

import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit


HARNESS = r"""
const fs = require('fs');
const elements = {
  'storage-backend': {
    value: 's3_compatible',
    options: [{value: 'local_filesystem', text: 'Local filesystem'},
              {value: 's3_compatible', text: 'S3-compatible'}],
  },
  's3-auth-mode': {value: 'iam_role'},
  's3-endpoint-url': {value: ''},
  's3-bucket': {value: 'bucket-b'},
  's3-access-key-id': {value: ''},
  's3-secret-access-key': {value: ''},
  's3-assume-role-arn': {value: ''},
  's3-region': {value: 'eu-west-1'},
  's3-prefix': {value: 'certmate/certificates'},
  'settingsDebugOutput': {appendChild() {}},
};
const requests = [], messages = [];
global.Option = function(text, value) { this.text = text; this.value = value; };
global.window = {};
global.CertMate = {
  escapeHtml: s => s, formatTime: () => '',
  toast: (message, type) => messages.push({message, type}),
};
global.fetch = (url, opts) => {
  requests.push({url, payload: JSON.parse(opts.body)});
  return Promise.resolve({ok: true, json: () => Promise.resolve({success: true, total: 0})});
};
global.document = {
  getElementById: id => elements[id] || null,
  createElement() {
    return {
      setAttribute() {}, addEventListener() {},
      remove() { delete elements.storageMigrationModal; },
    };
  },
  addEventListener() {}, removeEventListener() {},
  body: {appendChild(modal) {
    elements.storageMigrationModal = modal;
    const options = [...modal.innerHTML.matchAll(/<option value="([^"]*)">([^<]*)<\/option>/g)]
      .map(([, value, text]) => new Option(text, value));
    elements.storageMigSource = {
      options, value: options[0].value,
      add(option) { options.push(option); },
    };
    for (const id of ['storageMigCloseBtn', 'storageMigCancelBtn', 'storageMigStartBtn']) {
      elements[id] = {addEventListener() {}};
    }
  }},
};
// Only expose a test hook for currentSettings; exercise the real dialog and
// request builders, not a reimplementation of their selection logic.
const source = fs.readFileSync(process.argv[1], 'utf8').replace(
  'window.CmSettings = {',
  'window.__setMigrationSettings = s => { currentSettings = s; }; window.CmSettings = {');
eval(source);
window.__setMigrationSettings({certificate_storage: {
  backend: 's3_compatible', s3_compatible: {bucket: 'bucket-a', auth_mode: 'iam_role'},
}});

function check(condition, message) { if (!condition) throw new Error(message); }

// Saved S3 bucket A, unsaved target S3 bucket B: do not silently use local.
window.showStorageMigrationModal();
check(elements.storageMigSource.value === '', 'source was silently preselected');
check(elements.storageMigSource.options.some(o => o.value === 's3_compatible'), 'saved S3 source missing');
window.performStorageMigration();
check(requests.length === 0, 'request sent without an explicit source');
check(messages.some(m => m.type === 'error' && m.message.includes('source')), 'missing source not explained');

elements.storageMigSource.value = 's3_compatible';
window.performStorageMigration();
check(requests.length === 1, 'S3-to-S3 migration not sent');
check(requests[0].payload.source_backend === 's3_compatible', 'wrong source for bucket A');
check(requests[0].payload.target_config.s3_compatible.bucket === 'bucket-b', 'wrong target bucket');

// The recovery path still allows local source after S3 has already been saved.
window.showStorageMigrationModal();
elements.storageMigSource.value = 'local_filesystem';
window.performStorageMigration();
check(requests[1].payload.source_backend === 'local_filesystem', 'local recovery source lost');
"""


def test_source_selection_with_saved_s3_and_unsaved_bucket_edit(node):
    script = Path(__file__).resolve().parent.parent / 'static/js/settings.js'
    result = subprocess.run([node, '-e', HARNESS, str(script)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
