/**
 * CertMate shared utilities
 * Loaded globally via base.html
 */
(function(window) {
    'use strict';

    var CM = {};

    // ── HTML Escaping ────────────────────────────────────────────
    CM.escapeHtml = function(str) {
        if (str == null) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };

    // ── Tagged-template HTML builder ─────────────────────────────
    // Usage:  el.innerHTML = CertMate.html`<div title="${userText}">...</div>`;
    // Each ${value} is auto-escaped. Pre-rendered fragments must be wrapped
    // with CertMate.raw(...) to opt out (e.g. nested templates, icon HTML).
    // Arrays are joined; their elements are escaped or kept-raw the same way.
    function HtmlSafe(s) { this.s = String(s); }
    CM.raw = function(s) { return new HtmlSafe(s == null ? '' : s); };
    CM.html = function(strings /*, ...values */) {
        var out = strings[0];
        for (var i = 1; i < arguments.length; i++) {
            var v = arguments[i];
            if (v instanceof HtmlSafe) {
                out += v.s;
            } else if (Array.isArray(v)) {
                for (var j = 0; j < v.length; j++) {
                    var x = v[j];
                    out += (x instanceof HtmlSafe) ? x.s : CM.escapeHtml(x);
                }
            } else if (v == null || v === false) {
                // null / undefined / false render as empty (handy for ?: branches)
            } else {
                out += CM.escapeHtml(v);
            }
            out += strings[i];
        }
        return out;
    };

    // ── Toast Notifications ──────────────────────────────────────
    var toastContainer = null;

    function ensureToastContainer() {
        if (toastContainer && document.body.contains(toastContainer)) return toastContainer;
        toastContainer = document.createElement('div');
        toastContainer.id = 'cm-toasts';
        toastContainer.className = 'fixed top-4 right-4 z-[9999] flex flex-col gap-3 max-w-sm w-full pointer-events-none';
        document.body.appendChild(toastContainer);
        return toastContainer;
    }

    var TOAST_ICONS = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };

    var TOAST_COLORS = {
        success: 'bg-green-50 dark:bg-green-900/40 border-green-300 dark:border-green-700 text-green-800 dark:text-green-200',
        error: 'bg-red-50 dark:bg-red-900/40 border-red-300 dark:border-red-700 text-red-800 dark:text-red-200',
        warning: 'bg-yellow-50 dark:bg-yellow-900/40 border-yellow-300 dark:border-yellow-700 text-yellow-800 dark:text-yellow-200',
        info: 'bg-blue-50 dark:bg-blue-900/40 border-blue-300 dark:border-blue-700 text-blue-800 dark:text-blue-200'
    };

    CM.toast = function(message, type, duration, options) {
        type = type || 'info';
        // When an errorContext is supplied, give the user time to find
        // the Report button before the toast auto-dismisses. 10s vs the
        // 5s default — still goes away on its own so a chatty page
        // doesn't grow a pile of toasts.
        if (duration === undefined || duration === null) {
            duration = (options && options.errorContext) ? 10000 : 5000;
        }
        var container = ensureToastContainer();
        var opts = options || {};

        // Render the "Report this issue" button when (a) the caller
        // supplied an errorContext (so there's something to report),
        // (b) the type is error (we don't want to clutter success
        // toasts with a bug report affordance), and (c) the current
        // user role is admin — the diagnostics snapshot endpoint
        // is admin-only and a viewer click would just 403.
        var canReport = (
            type === 'error' &&
            opts.errorContext &&
            CM.role === 'admin' &&
            typeof CM.reportIssue === 'function'
        );

        var toast = document.createElement('div');
        toast.className = 'pointer-events-auto relative border rounded-lg shadow-lg p-4 flex flex-col gap-2 transform translate-x-full opacity-0 transition-all duration-300 overflow-hidden ' + (TOAST_COLORS[type] || TOAST_COLORS.info);

        var headerHtml =
            '<div class="flex items-start gap-3">' +
                '<i class="fas ' + (TOAST_ICONS[type] || TOAST_ICONS.info) + ' text-lg mt-0.5 flex-shrink-0"></i>' +
                '<div class="flex-1 text-sm font-medium">' + CM.escapeHtml(message) + '</div>' +
                '<button class="flex-shrink-0 text-current opacity-50 hover:opacity-100" data-action="dismiss">' +
                '<i class="fas fa-times"></i></button>' +
            '</div>';

        var reportRowHtml = canReport
            ? '<div class="pl-7 flex justify-start">' +
                  '<button data-action="report" class="text-xs font-medium underline opacity-80 hover:opacity-100 disabled:opacity-40 disabled:no-underline disabled:cursor-wait">' +
                      '<i class="fas fa-bug mr-1"></i>Report this issue' +
                  '</button>' +
              '</div>'
            : '';

        var progressHtml = duration > 0
            ? '<div class="toast-progress" style="--toast-duration:' + duration + 'ms"></div>'
            : '';

        toast.innerHTML = headerHtml + reportRowHtml + progressHtml;

        container.appendChild(toast);

        toast.querySelector('[data-action="dismiss"]').addEventListener('click', function () {
            toast.remove();
        });

        if (canReport) {
            var reportBtn = toast.querySelector('[data-action="report"]');
            reportBtn.addEventListener('click', function () {
                reportBtn.disabled = true;
                reportBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Preparing…';
                CM.reportIssue(opts.errorContext)['finally'](function () {
                    reportBtn.disabled = false;
                    reportBtn.innerHTML = '<i class="fas fa-bug mr-1"></i>Report this issue';
                });
            });
        }

        // Animate in
        requestAnimationFrame(function() {
            toast.classList.remove('translate-x-full', 'opacity-0');
            toast.classList.add('translate-x-0', 'opacity-100');
        });

        // Auto dismiss
        if (duration > 0) {
            setTimeout(function() {
                toast.classList.add('translate-x-full', 'opacity-0');
                setTimeout(function() { toast.remove(); }, 300);
            }, duration);
        }

        return toast;
    };

    // ── Current-user role (cross-page) ───────────────────────────
    // dashboard.js has had its own currentRole for a while; we mirror it
    // here on CM.role so report-issue.js (and any future cross-page
    // helper) can gate UI without depending on dashboard.js being
    // loaded — e.g. /settings doesn't load it. The two stores converge:
    // refreshRole() is idempotent and dashboard.js's loadCertificates
    // continues to drive its own local copy.
    CM.role = 'viewer';
    CM.ROLE_LEVELS = { viewer: 0, operator: 1, admin: 2 };
    CM.roleAtLeast = function (name) {
        return (CM.ROLE_LEVELS[CM.role] || 0) >= (CM.ROLE_LEVELS[name] || 0);
    };
    CM.refreshRole = function () {
        return fetch('/api/auth/me', { credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (data && data.user && data.user.role) {
                    CM.role = data.user.role;
                }
            })
            .catch(function () { /* keep last-known role */ });
    };
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', CM.refreshRole);
    } else {
        CM.refreshRole();
    }

    // ── Styled Confirm Dialog ────────────────────────────────────
    function createOverlay() {
        var overlay = document.createElement('div');
        overlay.className = 'fixed inset-0 z-[10000] flex items-center justify-center p-4';
        overlay.innerHTML = '<div class="absolute inset-0 bg-black/50 backdrop-blur-sm"></div>';
        return overlay;
    }

    function createDialogBox(title, bodyHtml) {
        var box = document.createElement('div');
        box.className = 'relative bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-md border border-gray-200 dark:border-gray-700 transform scale-95 opacity-0 transition-all duration-200';
        box.innerHTML =
            '<div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">' +
                '<h3 class="text-lg font-semibold text-gray-900 dark:text-white">' + CM.escapeHtml(title) + '</h3>' +
            '</div>' +
            '<div class="px-6 py-4">' + bodyHtml + '</div>';
        return box;
    }

    function animateIn(overlay, box) {
        document.body.appendChild(overlay);
        requestAnimationFrame(function() {
            box.classList.remove('scale-95', 'opacity-0');
            box.classList.add('scale-100', 'opacity-100');
        });
    }

    function animateOut(overlay) {
        var box = overlay.querySelector('.relative');
        if (box) {
            box.classList.add('scale-95', 'opacity-0');
            box.classList.remove('scale-100', 'opacity-100');
        }
        setTimeout(function() { overlay.remove(); }, 200);
    }

    var BTN_BASE = 'px-4 py-2 rounded-lg text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 dark:focus:ring-offset-gray-800';
    var BTN_CANCEL = BTN_BASE + ' bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 focus:ring-gray-300';
    var BTN_DANGER = BTN_BASE + ' bg-red-600 text-white hover:bg-red-700 focus:ring-red-500';
    var BTN_PRIMARY = BTN_BASE + ' bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500';

    CM.confirm = function(message, title, options) {
        title = title || 'Confirm';
        options = options || {};
        var danger = options.danger !== false; // default to danger styling

        return new Promise(function(resolve) {
            var overlay = createOverlay();
            var bodyHtml =
                '<p class="text-gray-600 dark:text-gray-300 text-sm">' + CM.escapeHtml(message) + '</p>' +
                '<div class="flex justify-end gap-3 mt-6">' +
                    '<button data-action="cancel" class="' + BTN_CANCEL + '">Cancel</button>' +
                    '<button data-action="confirm" class="' + (danger ? BTN_DANGER : BTN_PRIMARY) + '">' + CM.escapeHtml(options.confirmText || 'Confirm') + '</button>' +
                '</div>';

            var box = createDialogBox(title, bodyHtml);
            overlay.appendChild(box);
            animateIn(overlay, box);

            var confirmBtn = box.querySelector('[data-action="confirm"]');
            var cancelBtn = box.querySelector('[data-action="cancel"]');

            function close(result) {
                animateOut(overlay);
                resolve(result);
            }

            confirmBtn.addEventListener('click', function() { close(true); });
            cancelBtn.addEventListener('click', function() { close(false); });
            overlay.querySelector('.absolute').addEventListener('click', function() { close(false); });

            // Focus confirm button, handle Escape
            setTimeout(function() { confirmBtn.focus(); }, 50);
            overlay.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') close(false);
            });
        });
    };

    // ── Styled Prompt Dialog ─────────────────────────────────────
    CM.prompt = function(message, title, defaultValue) {
        title = title || 'Input';
        defaultValue = defaultValue || '';

        return new Promise(function(resolve) {
            var overlay = createOverlay();
            var inputId = 'cm-prompt-' + Date.now();
            var bodyHtml =
                '<label for="' + inputId + '" class="block text-gray-600 dark:text-gray-300 text-sm mb-3">' + CM.escapeHtml(message) + '</label>' +
                '<input id="' + inputId + '" type="text" value="' + CM.escapeHtml(defaultValue) + '" ' +
                    'class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none">' +
                '<div class="flex justify-end gap-3 mt-6">' +
                    '<button data-action="cancel" class="' + BTN_CANCEL + '">Cancel</button>' +
                    '<button data-action="confirm" class="' + BTN_PRIMARY + '">OK</button>' +
                '</div>';

            var box = createDialogBox(title, bodyHtml);
            overlay.appendChild(box);
            animateIn(overlay, box);

            var input = box.querySelector('input');
            var confirmBtn = box.querySelector('[data-action="confirm"]');
            var cancelBtn = box.querySelector('[data-action="cancel"]');

            function close(value) {
                animateOut(overlay);
                resolve(value);
            }

            confirmBtn.addEventListener('click', function() { close(input.value); });
            cancelBtn.addEventListener('click', function() { close(null); });
            overlay.querySelector('.absolute').addEventListener('click', function() { close(null); });

            input.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') close(input.value);
                if (e.key === 'Escape') close(null);
            });

            setTimeout(function() { input.focus(); input.select(); }, 50);
        });
    };

    // ── API Fetch Wrapper ────────────────────────────────────────
    CM.api = function(method, url, data, options) {
        options = options || {};
        var fetchOptions = {
            method: method,
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' }
        };
        if (data && method !== 'GET') {
            fetchOptions.body = JSON.stringify(data);
        }
        return fetch(url, fetchOptions).then(function(response) {
            if (response.status === 401) {
                window.location.href = '/login';
                return Promise.reject(new Error('Unauthorized'));
            }
            if (!response.ok) {
                return response.json().catch(function() {
                    return { error: 'Request failed (' + response.status + ')' };
                }).then(function(body) {
                    var err = new Error(body.error || body.message || 'Request failed');
                    err.status = response.status;
                    err.body = body;
                    return Promise.reject(err);
                });
            }
            if (response.status === 204) return null;
            return response.json();
        });
    };

    // ── Debug Logger ─────────────────────────────────────────────
    CM.debug = {
        _container: null,
        _output: null,

        init: function(containerId, outputId) {
            this._container = document.getElementById(containerId || 'debugConsole');
            this._output = document.getElementById(outputId || 'debugOutput');
        },

        log: function(message, type) {
            type = type || 'info';
            var output = this._output || document.getElementById('debugOutput');
            if (!output) return;

            var colors = { info: '#60a5fa', success: '#4ade80', error: '#f87171', warning: '#fbbf24' };
            var now = new Date().toLocaleTimeString();
            var entry = document.createElement('div');
            entry.style.cssText = 'padding:2px 0;border-bottom:1px solid rgba(255,255,255,0.1)';
            entry.innerHTML = '<span style="color:#9ca3af">[' + now + ']</span> ' +
                '<span style="color:' + (colors[type] || colors.info) + '">' + CM.escapeHtml(message) + '</span>';
            output.appendChild(entry);
            output.scrollTop = output.scrollHeight;
        },

        toggle: function() {
            var container = this._container || document.getElementById('debugConsole');
            if (container) container.classList.toggle('hidden');
        },

        clear: function() {
            var output = this._output || document.getElementById('debugOutput');
            if (output) output.innerHTML = '';
        }
    };

    // ── Modal standardization (R-2) ───────────────────────────────
    // Global behavior for any [data-modal-root] element: Esc key,
    // backdrop click, [data-modal-close] buttons, focus trap inside,
    // and a `modal:close` CustomEvent dispatched on dismiss so
    // callsites can subscribe for side-effects (form reset, body
    // overflow restore) without intercepting individual close
    // buttons. Visibility is still toggled by `.hidden` class — the
    // existing showLoadingModal / closeXxxModal helpers don't have
    // to change shape.
    var FOCUSABLE_SELECTOR =
        'a[href], button:not([disabled]), textarea:not([disabled]), ' +
        'input:not([disabled]):not([type="hidden"]), select:not([disabled]), ' +
        '[tabindex]:not([tabindex="-1"])';
    var modalLastFocus = (typeof WeakMap !== 'undefined') ? new WeakMap() : null;

    function isModalVisible(el) {
        return el && el.matches && el.matches('[data-modal-root]')
            && !el.classList.contains('hidden');
    }

    function visibleModal() {
        var roots = document.querySelectorAll('[data-modal-root]');
        for (var i = roots.length - 1; i >= 0; i--) {
            if (isModalVisible(roots[i])) return roots[i];
        }
        return null;
    }

    function focusableIn(root) { return root.querySelectorAll(FOCUSABLE_SELECTOR); }

    function dismissModal(root) {
        if (!root || root.hasAttribute('data-modal-no-dismiss')) return;
        root.classList.add('hidden');
        root.dispatchEvent(new CustomEvent('modal:close', { bubbles: false }));
    }

    CM.modal = {
        open: function(id) {
            var root = document.getElementById(id);
            if (!root) return;
            if (modalLastFocus) modalLastFocus.set(root, document.activeElement);
            root.classList.remove('hidden');
            var f = focusableIn(root);
            if (f.length > 0) f[0].focus();
            root.dispatchEvent(new CustomEvent('modal:open', { bubbles: false }));
        },
        close: function(id) {
            var root = document.getElementById(id);
            dismissModal(root);
        }
    };

    // Esc to close + Tab to trap focus inside the topmost open modal.
    document.addEventListener('keydown', function(e) {
        var root = visibleModal();
        if (!root) return;
        if (e.key === 'Escape' && !root.hasAttribute('data-modal-no-dismiss')) {
            e.preventDefault();
            dismissModal(root);
            return;
        }
        if (e.key === 'Tab') {
            var f = focusableIn(root);
            if (f.length === 0) { e.preventDefault(); return; }
            var first = f[0], last = f[f.length - 1];
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault(); last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault(); first.focus();
            }
        }
    });

    // [data-modal-close] anywhere, or click on the root itself (backdrop).
    document.addEventListener('click', function(e) {
        var closeBtn = e.target.closest && e.target.closest('[data-modal-close]');
        if (closeBtn) {
            var root = closeBtn.closest('[data-modal-root]');
            if (root) dismissModal(root);
            return;
        }
        var clickedRoot = e.target.closest && e.target.closest('[data-modal-root]');
        if (clickedRoot && e.target === clickedRoot) {
            dismissModal(clickedRoot);
        }
    });

    // Observe `.hidden` class toggles to auto-focus on open and
    // restore focus on close. Existing callsites that call
    // `.classList.remove('hidden')` directly (e.g. showLoadingModal,
    // showCurlModal flows) get focus management for free.
    if (typeof MutationObserver !== 'undefined' && modalLastFocus) {
        var modalObserver = new MutationObserver(function(mutations) {
            mutations.forEach(function(m) {
                if (m.attributeName !== 'class') return;
                var t = m.target;
                if (!t.matches('[data-modal-root]')) return;
                var wasHidden = m.oldValue ? m.oldValue.indexOf('hidden') !== -1 : false;
                var isHidden = t.classList.contains('hidden');
                if (wasHidden && !isHidden) {
                    modalLastFocus.set(t, document.activeElement);
                    var f = focusableIn(t);
                    if (f.length > 0) f[0].focus();
                } else if (!wasHidden && isHidden) {
                    var prev = modalLastFocus.get(t);
                    if (prev && typeof prev.focus === 'function') {
                        try { prev.focus(); } catch (e) { /* element gone */ }
                    }
                }
            });
        });
        // Attach the observer to every modal root. If the script loaded
        // BEFORE DOMContentLoaded we have to wait for it (the roots may not
        // exist yet); if it loaded AFTER (defer / dynamic import), the event
        // has already fired and `addEventListener` would silently never run —
        // leaving modals without Esc / backdrop / focus-trap support. Mirror
        // the readyState pattern used by CM.refreshRole above.
        function _attachModalObservers() {
            document.querySelectorAll('[data-modal-root]').forEach(function(root) {
                modalObserver.observe(root, {
                    attributes: true, attributeFilter: ['class'], attributeOldValue: true
                });
            });
        }
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', _attachModalObservers);
        } else {
            _attachModalObservers();
        }
    }

    // ── Debug-console gating ─────────────────────────────────────
    // The Debug button + console in index.html / settings.html are
    // dev-only surfaces. Show them only when explicitly opted in via
    // `?debug=1` in the URL (persisted to localStorage, so once
    // toggled it stays on for the session/install) or by setting
    // localStorage.certmate_debug = '1' directly. `?debug=0` clears
    // the flag.
    try {
        var params = new URLSearchParams(window.location.search);
        if (params.has('debug')) {
            if (params.get('debug') === '0') {
                localStorage.removeItem('certmate_debug');
            } else {
                localStorage.setItem('certmate_debug', '1');
            }
        }
    } catch (e) { /* old browser or storage disabled */ }

    CM.debugEnabled = (function() {
        try { return localStorage.getItem('certmate_debug') === '1'; }
        catch (e) { return false; }
    })();

    // Even with `?debug=1` explicitly opted-in, gate the actual unhide
    // on the caller being an admin. The debug surfaces leak internal
    // information (deployment-probe logs, cache hit/miss counters,
    // settings shape, etc.) that shouldn't be visible to viewer or
    // operator roles even if they figure out the URL flag — defense in
    // depth on top of the URL opt-in (8.2 fix).
    if (CM.debugEnabled) {
        document.addEventListener('DOMContentLoaded', function() {
            fetch('/api/auth/me', { credentials: 'same-origin' })
                .then(function(r) { return r.ok ? r.json() : null; })
                .then(function(data) {
                    if (!data || !data.user || data.user.role !== 'admin') return;
                    document.querySelectorAll('[data-debug-control]').forEach(function(el) {
                        el.classList.remove('hidden');
                    });
                })
                .catch(function() { /* network/parse error: leave debug hidden */ });
        });
    }

    // ── Expose globally ──────────────────────────────────────────
    window.CertMate = CM;

})(window);
