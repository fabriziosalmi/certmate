/**
 * Settings asks before leaving with changes nobody saved.
 *
 * The UX audit of 2026-11-17 changed the renewal threshold from 30 to 21 and
 * left the page: no prompt, and the server still had 30. A webhook added on
 * Notifications was lost the same way. The page has seven save buttons, and
 * some sections apply at once (users, API keys, probe targets), so the guard
 * is told, in the markup, what is saved by a button:
 *
 *   [data-unsaved-scope]  a part of the page that its own Save button saves;
 *                         a real edit in it (not a value a script filled in)
 *                         marks it changed. Scopes can nest; the innermost wins.
 *   [data-saves]          that Save button. A write request that succeeds
 *                         right after a click on it marks its scope saved.
 *                         Submitting a form that is a scope does the same.
 *   [data-discards]       a Cancel that throws the scope's changes away.
 *
 * Edits inside a dialog and in search boxes are not settings and are ignored.
 * Leaving the page with a changed scope asks first (beforeunload).
 */
(function () {
    'use strict';

    var changed = new Set();
    var pending = null;          // {scope, at}: a save was asked for
    var SAVE_WINDOW_MS = 15000;

    function scopeOf(el) {
        return el && el.closest ? el.closest('[data-unsaved-scope]') : null;
    }

    function counts(target) {
        if (!target || !target.closest) return false;
        if (target.closest('[role=dialog], [data-modal-root], [aria-modal=true]')) return false;
        if (target.type === 'search' || target.type === 'file') return false;
        return true;
    }

    function markChanged(event) {
        if (!event.isTrusted || !counts(event.target)) return;
        var scope = scopeOf(event.target);
        if (scope) changed.add(scope);
    }

    document.addEventListener('input', markChanged, true);
    document.addEventListener('change', markChanged, true);

    document.addEventListener('click', function (event) {
        var control = event.target.closest && event.target.closest('[data-saves], [data-discards]');
        if (!control) return;
        var scope = scopeOf(control);
        if (!scope) return;
        if (control.hasAttribute('data-discards')) {
            changed.delete(scope);
            return;
        }
        pending = { scope: scope, at: Date.now() };
    }, true);

    document.addEventListener('submit', function (event) {
        if (event.target.hasAttribute && event.target.hasAttribute('data-unsaved-scope')) {
            pending = { scope: event.target, at: Date.now() };
        }
    }, true);

    // A save is done when the write it sends succeeds. The page's saves go
    // through fetch; reading the answer here keeps the seven of them unchanged.
    var realFetch = window.fetch;
    window.fetch = function (resource, options) {
        var method = ((options && options.method) || (resource && resource.method) || 'GET').toUpperCase();
        var asked = pending;
        return realFetch.apply(this, arguments).then(function (response) {
            if (method !== 'GET' && response.ok && asked && pending === asked &&
                    Date.now() - asked.at < SAVE_WINDOW_MS) {
                changed.delete(asked.scope);
                // Everything inside a saved scope was saved with it.
                changed.forEach(function (scope) {
                    if (asked.scope.contains(scope)) changed.delete(scope);
                });
                pending = null;
            }
            return response;
        });
    };

    function unsaved() {
        var open = [];
        changed.forEach(function (scope) {
            if (scope.isConnected) open.push(scope.getAttribute('data-unsaved-scope'));
        });
        return open;
    }

    window.addEventListener('beforeunload', function (event) {
        if (!unsaved().length) return;
        event.preventDefault();
        // Older browsers need returnValue set; the text is not shown any more.
        event.returnValue = '';
    });

    window.CertMate = window.CertMate || {};
    window.CertMate.unsavedSettings = unsaved;
})();
