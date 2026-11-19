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
 * While a save is on its way its section takes no edits: its text fields are
 * read-only and its boxes, radios, lists and chips refuse a change, the
 * section and its Save are aria-busy and "Saving…" stands beside the Save,
 * focus stays where it was, and all of it is released once the save has
 * settled (success or failure) and the read some sections make after it is
 * done. An edit typed then would be sent by no one and, where the section
 * reads itself back, overwritten.
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
    // What a field held just before the user last reached it (focus, a key,
    // a press): its start once the first edit comes. Only an edit fixes it,
    // so a field reached before the page's load filled it starts from the
    // loaded value, not from the empty one.
    var reached = new Map();
    var UNKNOWN = {};            // a start that cannot be known: always a change
    var pending = null;          // {scope, at, claimed, sent}: a save was asked for
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
        // A control removed by an edit (a deleted webhook) is a change until
        // the section is saved; one its section redrew after a save (the SSO
        // form is rebuilt by its read) is not.
        if (!el.isConnected) return !entry.afterSave;
        return entry.value === UNKNOWN || current(el) !== entry.value;
    }

    // The value a text field or a list holds as the user reaches it, kept
    // until the first edit (see `reached`).
    function remember(event) {
        var el = event.target;
        if (!event.isTrusted || !isField(el) || el.type === 'checkbox' || el.type === 'radio') return;
        if (originals.has(el) || !counts(el)) return;
        reached.set(el, el.value);
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

    // What a save sends is what its section holds when the request goes:
    // each edited control of the section, its value then, and how many
    // edits it had seen.
    function snapshot(scope) {
        var sent = new Map();
        originals.forEach(function (entry, el) {
            if (covers(scope, entry.scope)) sent.set(el, { value: current(el), edits: entry.edits });
        });
        return sent;
    }

    // A save that succeeded: a control not edited since its request went is
    // saved; one edited since starts from what was sent, so it still reads
    // unsaved while it differs from that.
    function settle(scope, sent) {
        originals.forEach(function (entry, el) {
            if (!covers(scope, entry.scope)) return;
            var then = sent ? sent.get(el) : null;
            if (sent && !then) return;                   // first edited after the request went
            if (!then || entry.edits === then.edits) originals.delete(el);
            else originals.set(el, { value: then.value, scope: entry.scope, edits: entry.edits, afterSave: true });
        });
        recount();
    }

    // ── A section takes no edits while its save is on its way ──────────
    var locks = [];              // {scope, button, fields, inflight, cap}

    function lockFor(el) {
        if (!el || !el.closest || el.closest('[data-applies-now]')) return null;
        for (var i = 0; i < locks.length; i++) {
            var inner = scopeOf(el);
            if (inner && locks[i].scope.contains(el) && covers(locks[i].scope, inner)) return locks[i];
        }
        return null;
    }

    function lock(scope, button) {
        for (var i = 0; i < locks.length; i++) {
            if (locks[i].scope === scope) return locks[i];
        }
        var held = { scope: scope, button: button, fields: [], inflight: 0, cap: null };
        scope.querySelectorAll('input, textarea').forEach(function (el) {
            if (['checkbox', 'radio', 'hidden', 'button', 'submit', 'reset'].indexOf(el.type) !== -1) return;
            if (!counts(el) || !covers(scope, scopeOf(el))) return;
            held.fields.push({ el: el, readOnly: el.readOnly });
            el.readOnly = true;
        });
        scope.setAttribute('aria-busy', 'true');
        if (button) button.setAttribute('aria-busy', 'true');
        locks.push(held);
        held.cap = setTimeout(function () { release(held); }, 20000);
        showMarkers();
        whenQuiet(held);
        return held;
    }

    function release(held) {
        var at = locks.indexOf(held);
        if (at === -1) return;
        locks.splice(at, 1);
        clearTimeout(held.cap);
        held.fields.forEach(function (field) { field.el.readOnly = field.readOnly; });
        held.scope.removeAttribute('aria-busy');
        if (held.button) held.button.removeAttribute('aria-busy');
        recount();
    }

    // Released once nothing the page asked for since the lock is still on its
    // way, and the page has had its turn with the last answer: a click that
    // sent nothing is released at once, a save that reads its section back
    // after it is released when that read has been applied.
    function whenQuiet(held) {
        setTimeout(function () {
            if (held.inflight === 0) release(held);
        }, 0);
    }

    function follow(answer, held) {
        if (!held.length) return answer;
        held.forEach(function (h) { h.inflight++; });
        var done = false;
        function finish() {
            if (done) return;
            done = true;
            held.forEach(function (h) { h.inflight--; whenQuiet(h); });
        }
        return answer.then(function (response) {
            var reading = false;
            ['json', 'text', 'blob', 'arrayBuffer', 'formData'].forEach(function (name) {
                var read = response[name];
                if (typeof read !== 'function') return;
                response[name] = function () {
                    reading = true;
                    return read.apply(response, arguments).then(function (value) {
                        finish();
                        return value;
                    }, function (error) {
                        finish();
                        throw error;
                    });
                };
            });
            setTimeout(function () { if (!reading) finish(); }, 0);
            return response;
        }, function (error) {
            finish();
            throw error;
        });
    }

    // A change to a held section is refused where it would happen: a box, a
    // radio or a chip is not toggled, a list does not open. Text fields are
    // read-only, which leaves the focus where it is.
    function refuse(event) {
        var el = event.target;
        if (!isField(el) || !lockFor(el)) return;
        if (event.type === 'click' && el.type !== 'checkbox' && el.type !== 'radio') return;
        if (event.type !== 'click' && el.tagName !== 'SELECT') return;
        if (event.type === 'keydown' && (event.key === 'Tab' || event.key === 'Escape')) return;
        event.preventDefault();
        event.stopImmediatePropagation();
    }
    document.addEventListener('click', refuse, true);
    document.addEventListener('mousedown', refuse, true);
    document.addEventListener('keydown', refuse, true);

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
            var saving = locks.some(function (h) { return h.scope === scope; });
            var show = saving || changed.has(scope);
            if (!has) {
                if (!show) return;
                marker = document.createElement('span');
                marker.setAttribute('data-unsaved-marker', '');
                marker.className = 'self-center mr-3 text-xs font-medium text-warning-fg';
                button.parentNode.insertBefore(marker, button);
            }
            marker.textContent = saving ? 'Saving…' : 'Unsaved changes';
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
        var entry = originals.get(el);
        if (!entry) {
            // A box was the other way before this change; a field reached
            // with no focus or keystroke seen first cannot be known.
            var start = el.type === 'checkbox' ? !el.checked : (reached.has(el) ? reached.get(el) : UNKNOWN);
            reached.delete(el);
            entry = { value: start, scope: scope, edits: 0 };
            originals.set(el, entry);
        }
        entry.edits++;
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
    document.addEventListener('pointerdown', remember, true);
    document.addEventListener('keydown', remember, true);
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
            settle(scope, null);
            return;
        }
        pending = { scope: scope, at: Date.now(), claimed: false };
        // A submit button is held at the submit, once the browser's own
        // checks have passed: a read-only field is not checked at all, so
        // holding it at the click would let an invalid value through.
        if (!(control.type === 'submit' && control.form)) lock(scope, control);
    }, true);

    document.addEventListener('submit', function (event) {
        if (event.target.hasAttribute && event.target.hasAttribute('data-unsaved-scope')) {
            pending = { scope: event.target, at: Date.now(), claimed: false };
            lock(event.target, event.target.querySelector('[data-saves]'));
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
            asked.sent = snapshot(asked.scope);
            lock(asked.scope, null);
        }
        var answer = follow(realFetch.apply(this, arguments), locks.slice());
        if (!asked) return answer;
        return answer.then(function (response) {
            if (pending === asked) pending = null;
            if (response.ok) settle(asked.scope, asked.sent);
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
