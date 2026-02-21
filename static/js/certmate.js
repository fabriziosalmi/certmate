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

    CM.toast = function(message, type, duration) {
        type = type || 'info';
        duration = duration || 5000;
        var container = ensureToastContainer();

        var toast = document.createElement('div');
        toast.className = 'pointer-events-auto border rounded-lg shadow-lg p-4 flex items-start gap-3 transform translate-x-full opacity-0 transition-all duration-300 ' + (TOAST_COLORS[type] || TOAST_COLORS.info);

        toast.innerHTML =
            '<i class="fas ' + (TOAST_ICONS[type] || TOAST_ICONS.info) + ' text-lg mt-0.5 flex-shrink-0"></i>' +
            '<div class="flex-1 text-sm font-medium">' + CM.escapeHtml(message) + '</div>' +
            '<button class="flex-shrink-0 text-current opacity-50 hover:opacity-100" onclick="this.parentElement.remove()">' +
            '<i class="fas fa-times"></i></button>';

        container.appendChild(toast);

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

    // ── Expose globally ──────────────────────────────────────────
    window.CertMate = CM;

})(window);
