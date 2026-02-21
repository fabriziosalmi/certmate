/**
 * Keyboard Shortcuts — static/js/shortcuts.js
 * Global keyboard shortcuts for power-user navigation and actions.
 * Loaded after certmate.js in base.html.
 */
(function() {
    'use strict';

    var shortcutOverlay = null;

    var shortcuts = [
        { key: '?', desc: 'Show keyboard shortcuts' },
        { key: '/', desc: 'Focus search / filter' },
        { key: 'n', desc: 'New certificate (focus domain input)' },
        { key: 'r', desc: 'Refresh certificate list' },
        { key: 't', desc: 'Toggle dark mode' },
        { key: 'g h', desc: 'Go to Certificates' },
        { key: 'g c', desc: 'Go to Client Certificates' },
        { key: 'g s', desc: 'Go to Settings' },
        { key: 'g a', desc: 'Go to Activity' },
        { key: 'g d', desc: 'Go to API Docs' },
        { key: 'Esc', desc: 'Close panel / overlay' }
    ];

    // "g" prefix state for two-key navigation combos
    var gPending = false;
    var gTimer = null;

    function isInputFocused() {
        var el = document.activeElement;
        if (!el) return false;
        var tag = el.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
        if (el.isContentEditable) return true;
        return false;
    }

    function createOverlay() {
        var div = document.createElement('div');
        div.id = 'shortcutOverlay';
        div.className = 'fixed inset-0 z-[101] hidden';
        var cols = '';
        shortcuts.forEach(function(s) {
            var keys = s.key.split(' ');
            var kbds = keys.map(function(k) {
                return '<kbd class="inline-flex items-center justify-center min-w-[28px] px-2 py-1 text-xs font-mono font-semibold ' +
                    'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 border border-gray-300 dark:border-gray-600 rounded shadow-sm">' +
                    CertMate.escapeHtml(k) + '</kbd>';
            }).join('<span class="mx-1 text-gray-400 text-xs">then</span>');
            cols += '<div class="flex items-center justify-between py-1.5">' +
                '<span class="text-sm text-gray-700 dark:text-gray-300">' + CertMate.escapeHtml(s.desc) + '</span>' +
                '<span class="ml-4 flex items-center gap-1">' + kbds + '</span>' +
                '</div>';
        });

        div.innerHTML =
            '<div class="fixed inset-0 bg-black/50 backdrop-blur-sm" id="shortcutOverlayBg"></div>' +
            '<div class="fixed inset-x-4 top-[12vh] sm:inset-x-auto sm:left-1/2 sm:-translate-x-1/2 sm:w-full sm:max-w-md ' +
                'bg-white dark:bg-gray-800 rounded-xl shadow-2xl border border-gray-200 dark:border-gray-700 overflow-hidden">' +
                '<div class="px-5 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">' +
                    '<h3 class="text-sm font-semibold text-gray-900 dark:text-white"><i class="fas fa-keyboard mr-2 text-gray-400"></i>Keyboard Shortcuts</h3>' +
                    '<button type="button" id="shortcutOverlayClose" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200" title="Close">' +
                        '<i class="fas fa-times"></i>' +
                    '</button>' +
                '</div>' +
                '<div class="px-5 py-3 divide-y divide-gray-100 dark:divide-gray-700/50">' + cols + '</div>' +
                '<div class="px-5 py-2 border-t border-gray-200 dark:border-gray-700 text-xs text-gray-400 text-center">' +
                    'Press <kbd class="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs">?</kbd> to toggle &middot; ' +
                    '<kbd class="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs">Esc</kbd> to close' +
                '</div>' +
            '</div>';

        document.body.appendChild(div);
        shortcutOverlay = div;

        document.getElementById('shortcutOverlayBg').addEventListener('click', closeOverlay);
        document.getElementById('shortcutOverlayClose').addEventListener('click', closeOverlay);
    }

    function openOverlay() {
        if (!shortcutOverlay) createOverlay();
        shortcutOverlay.classList.remove('hidden');
    }

    function closeOverlay() {
        if (shortcutOverlay) shortcutOverlay.classList.add('hidden');
    }

    function isOverlayOpen() {
        return shortcutOverlay && !shortcutOverlay.classList.contains('hidden');
    }

    function cancelG() {
        gPending = false;
        if (gTimer) {
            clearTimeout(gTimer);
            gTimer = null;
        }
    }

    document.addEventListener('keydown', function(e) {
        // Ignore when modifier keys are held (except Shift for ?)
        if (e.ctrlKey || e.metaKey || e.altKey) return;

        // Escape always works — close overlays/panels
        if (e.key === 'Escape') {
            if (isOverlayOpen()) {
                e.preventDefault();
                closeOverlay();
                return;
            }
            // Let other handlers (cmd-palette, cert detail) handle Escape
            cancelG();
            return;
        }

        // All other shortcuts suppressed when typing in inputs
        if (isInputFocused()) {
            cancelG();
            return;
        }

        // Handle "g" prefix combos
        if (gPending) {
            cancelG();
            e.preventDefault();
            switch (e.key) {
                case 'h': window.location.href = '/'; break;
                case 'c': window.location.href = '/#client'; break;
                case 's': window.location.href = '/settings'; break;
                case 'a': window.location.href = '/activity'; break;
                case 'd': window.location.href = '/redoc'; break;
            }
            return;
        }

        // Single-key shortcuts
        switch (e.key) {
            case '?':
                e.preventDefault();
                if (isOverlayOpen()) {
                    closeOverlay();
                } else {
                    openOverlay();
                }
                break;

            case '/':
                e.preventDefault();
                // Focus certificate search if on dashboard, otherwise open Cmd+K
                var searchEl = document.getElementById('certificateSearch');
                if (searchEl) {
                    searchEl.focus();
                    searchEl.select();
                } else {
                    // Trigger Cmd+K palette on non-dashboard pages
                    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true }));
                }
                break;

            case 'n':
                e.preventDefault();
                var domainInput = document.getElementById('domain');
                if (domainInput) {
                    domainInput.focus();
                    domainInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
                } else {
                    // Navigate to dashboard first
                    window.location.href = '/';
                }
                break;

            case 'r':
                e.preventDefault();
                if (typeof window.loadCertificates === 'function') {
                    window.loadCertificates();
                    if (typeof CertMate !== 'undefined' && CertMate.toast) {
                        CertMate.toast('Refreshing certificates...', 'info');
                    }
                }
                break;

            case 't':
                e.preventDefault();
                if (typeof toggleTheme === 'function') toggleTheme();
                break;

            case 'g':
                e.preventDefault();
                gPending = true;
                gTimer = setTimeout(cancelG, 1500);
                break;
        }
    });
})();
