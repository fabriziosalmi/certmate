/**
 * Settings asks before leaving with changes nobody saved.
 *
 * The UX audit of 2026-11-17 changed the renewal threshold from 30 to 21 and
 * left the page: no prompt, and the server still had 30. A webhook added on
 * Notifications was lost the same way. The page has several save buttons, and
 * some controls apply at once (users, API keys, adding or removing a probe),
 * so the guard is told, in the markup, what is saved by a button:
 *
 *   [data-unsaved-scope]  a part of the page that its own Save button saves;
 *                         a real edit in it (not a value a script filled in)
 *                         that leaves a control different from where it
 *                         started marks it changed; putting the control back
 *                         unmarks it. Scopes can nest; the innermost wins.
 *   [data-saves]          that Save button. The first write request after a
 *                         click on it is the save: when it succeeds, its scope
 *                         is saved, with any scope nested in it that has no
 *                         Save of its own; when it fails, nothing is saved.
 *                         Submitting a form that is a scope does the same.
 *   [data-discards]       a Cancel that throws the scope's changes away.
 *   [data-applies-now]    a control that writes as it changes, and says
 *                         "Applies immediately" on screen; it is never an
 *                         unsaved change, even inside a scope.
 *
 * Edits inside a dialog and in search boxes are not settings and are ignored.
 * Leaving the page with a changed scope asks first (beforeunload), and while
 * a scope is changed its Save buttons carry "Unsaved changes" beside them,
 * so a switch that waits for Save says so before anyone leaves (UX audit P28).
 */
(function () {
    'use strict';

    var changed = new Set();
    // Each control edited since its scope was last saved: where it started,
    // and the scope it belongs to (kept, so a control removed from the page,
    // such as a deleted webhook, still counts as a change).
    var originals = new Map();
    var UNKNOWN = {};            // a start that cannot be known: always a change
    var pending = null;          // {scope, at, claimed}: a save was asked for
    var SAVE_WINDOW_MS = 15000;

    function scopeOf(el) {
        return el && el.closest ? el.closest('[data-unsaved-scope]') : null;
    }

    function inDialog(el) {
        return !!(el && el.closest && el.closest('[role=dialog], [data-modal-root], [aria-modal=true]'));
    }

    function counts(target) {
        if (!target || !target.closest) return false;
        if (inDialog(target)) return false;
        if (target.type === 'search' || target.type === 'file') return false;
        if (target.closest('[data-applies-now]')) return false;
        return true;
    }

    function isField(el) {
        return !!el && (el.tagName === 'INPUT' || el.tagName === 'SELECT' || el.tagName === 'TEXTAREA');
    }

    function current(el) {
        if (el.type === 'checkbox') return el.checked;
        // Which radio of a group was ticked before is gone by the time the
        // change is seen, so a radio counts as changed until saved.
        if (el.type === 'radio') return UNKNOWN;
        return el.value;
    }

    function differs(el, entry) {
        if (!el.isConnected) return true;
        return entry.value === UNKNOWN || current(el) !== entry.value;
    }

    // The value a text field or a list had before the first edit.
    function remember(event) {
        var el = event.target;
        if (!event.isTrusted || !isField(el) || el.type === 'checkbox' || el.type === 'radio') return;
        if (originals.has(el) || !counts(el)) return;
        var scope = scopeOf(el);
        if (scope) originals.set(el, { value: el.value, scope: scope });
    }

    function hasOwnSave(scope) {
        var buttons = scope.querySelectorAll('[data-saves]');
        for (var i = 0; i < buttons.length; i++) {
            if (scopeOf(buttons[i]) === scope) return true;
        }
        return false;
    }

    // A save or a discard of *scope* covers the scopes inside it, except one
    // with a Save of its own: the deploy target editor is saved by Save
    // target, never by Save Deploy Settings.
    function covers(scope, inner) {
        if (inner === scope) return true;
        return scope.contains(inner) && !hasOwnSave(inner);
    }

    function settle(scope) {
        originals.forEach(function (entry, el) {
            if (covers(scope, entry.scope)) originals.delete(el);
        });
        recount();
    }

    function recount() {
        changed.clear();
        originals.forEach(function (entry, el) {
            if (!entry.scope.isConnected) {
                originals.delete(el);
                return;
            }
            if (differs(el, entry)) changed.add(entry.scope);
        });
        showMarkers();
    }

    // "Unsaved changes" beside each Save button whose scope holds a change.
    // The marker is made the first time it is needed and hidden after, so
    // nothing moves while the page loads.
    function showMarkers() {
        document.querySelectorAll('[data-saves]').forEach(function (button) {
            var scope = scopeOf(button);
            if (!scope) return;
            var marker = button.previousElementSibling;
            var has = marker && marker.hasAttribute('data-unsaved-marker');
            var show = changed.has(scope);
            if (!has) {
                if (!show) return;
                marker = document.createElement('span');
                marker.setAttribute('data-unsaved-marker', '');
                marker.className = 'self-center mr-3 text-xs font-medium text-warning-fg';
                marker.textContent = 'Unsaved changes';
                button.parentNode.insertBefore(marker, button);
            }
            marker.hidden = !show;
        });
    }

    // Anything the user does other than a save, before the save has sent its
    // write, means that click sent nothing (a check in the page stopped it):
    // a write after it belongs to something else.
    function forgetAnUnsentSave(event) {
        if (!event.isTrusted || !pending || pending.claimed || inDialog(event.target)) return;
        if (event.type === 'click' && event.target.closest && event.target.closest('[data-saves]')) return;
        pending = null;
    }

    function markChanged(event) {
        forgetAnUnsentSave(event);
        if (!event.isTrusted || !counts(event.target)) return;
        var el = event.target;
        var scope = scopeOf(el);
        if (!scope) return;
        if (!originals.has(el)) {
            // A box was the other way before this change; a field reached
            // with no focus or keystroke seen first cannot be known.
            var start = el.type === 'checkbox' ? !el.checked : UNKNOWN;
            originals.set(el, { value: start, scope: scope });
        }
        // Counted after the page's own handlers, which may put the control
        // back (the last event chip stays selected), and that is no change:
        // when the event bubbles up here, and once more after it in case a
        // handler stopped it on the way.
        setTimeout(recount, 0);
    }

    function recountAfterHandlers(event) {
        if (event.isTrusted) recount();
    }

    document.addEventListener('focusin', remember, true);
    document.addEventListener('beforeinput', remember, true);
    document.addEventListener('input', markChanged, true);
    document.addEventListener('change', markChanged, true);
    document.addEventListener('input', recountAfterHandlers);
    document.addEventListener('change', recountAfterHandlers);

    document.addEventListener('click', function (event) {
        forgetAnUnsentSave(event);
        var control = event.target.closest && event.target.closest('[data-saves], [data-discards]');
        if (!control) return;
        var scope = scopeOf(control);
        if (!scope) return;
        if (control.hasAttribute('data-discards')) {
            settle(scope);
            return;
        }
        pending = { scope: scope, at: Date.now(), claimed: false };
    }, true);

    document.addEventListener('submit', function (event) {
        if (event.target.hasAttribute && event.target.hasAttribute('data-unsaved-scope')) {
            pending = { scope: event.target, at: Date.now(), claimed: false };
        }
    }, true);

    // A save is done when the write it sends succeeds. The page's saves go
    // through fetch; reading the answer here keeps each of them unchanged.
    var realFetch = window.fetch;
    window.fetch = function (resource, options) {
        var method = ((options && options.method) || (resource && resource.method) || 'GET').toUpperCase();
        var asked = null;
        if (method !== 'GET' && pending && !pending.claimed && Date.now() - pending.at < SAVE_WINDOW_MS) {
            asked = pending;
            asked.claimed = true;
        }
        var answer = realFetch.apply(this, arguments);
        if (!asked) return answer;
        return answer.then(function (response) {
            if (pending === asked) pending = null;
            if (response.ok) settle(asked.scope);
            return response;
        }, function (error) {
            if (pending === asked) pending = null;
            throw error;
        });
    };

    function unsaved() {
        recount();
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
