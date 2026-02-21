/**
 * Cmd+K Global Search Palette — static/js/cmd-palette.js
 * Provides a spotlight-style search across navigation, settings, and certificates.
 */
(function() {
    'use strict';

    var escapeHtml = CertMate.escapeHtml;
    var paletteEl = null;
    var inputEl = null;
    var resultsEl = null;
    var selectedIndex = 0;
    var currentResults = [];
    var certCache = null;

    // Static searchable items
    var staticItems = [
        { type: 'nav', icon: 'fa-certificate', label: 'Server Certificates', desc: 'Manage SSL/TLS certificates', url: '/' },
        { type: 'nav', icon: 'fa-id-card', label: 'Client Certificates', desc: 'mTLS, VPN, user auth certificates', url: '/#client' },
        { type: 'nav', icon: 'fa-cog', label: 'Settings', desc: 'Configure DNS, CA, storage', url: '/settings' },
        { type: 'nav', icon: 'fa-question-circle', label: 'Help & Documentation', desc: 'Getting started, guides', url: '/help' },
        { type: 'nav', icon: 'fa-book', label: 'API Documentation', desc: 'ReDoc API reference', url: '/redoc' },
        { type: 'settings', icon: 'fa-server', label: 'DNS Provider Settings', desc: 'Configure DNS providers', url: '/settings#dns' },
        { type: 'settings', icon: 'fa-shield-alt', label: 'CA Settings', desc: 'Certificate authority configuration', url: '/settings#ca' },
        { type: 'settings', icon: 'fa-sliders-h', label: 'General Settings', desc: 'Notifications, defaults', url: '/settings#general' },
        { type: 'settings', icon: 'fa-database', label: 'Storage Settings', desc: 'Certificate storage paths', url: '/settings#storage' },
        { type: 'settings', icon: 'fa-users', label: 'User Management', desc: 'Manage user accounts', url: '/settings#users' },
        { type: 'settings', icon: 'fa-archive', label: 'Backup & Restore', desc: 'Backup configuration and certificates', url: '/settings#backup' },
        { type: 'action', icon: 'fa-plus-circle', label: 'Create Certificate', desc: 'Issue a new SSL certificate', url: '/', action: 'focusCreate' },
        { type: 'action', icon: 'fa-moon', label: 'Toggle Dark Mode', desc: 'Switch theme', action: 'toggleTheme' },
        { type: 'action', icon: 'fa-bell', label: 'Notifications', desc: 'Check certificate alerts', action: 'toggleNotifs' }
    ];

    function createPaletteHTML() {
        var div = document.createElement('div');
        div.id = 'cmdPalette';
        div.className = 'fixed inset-0 z-[100] hidden';
        div.innerHTML =
            '<div class="fixed inset-0 bg-black/50 backdrop-blur-sm" id="cmdPaletteOverlay"></div>' +
            '<div class="fixed inset-x-4 top-[15vh] sm:inset-x-auto sm:left-1/2 sm:-translate-x-1/2 sm:w-full sm:max-w-lg bg-white dark:bg-gray-800 rounded-xl shadow-2xl border border-gray-200 dark:border-gray-700 overflow-hidden">' +
                '<div class="flex items-center px-4 border-b border-gray-200 dark:border-gray-700">' +
                    '<i class="fas fa-search text-gray-400 mr-3"></i>' +
                    '<input id="cmdPaletteInput" type="text" placeholder="Search pages, settings, certificates..." ' +
                           'class="flex-1 py-3 bg-transparent text-gray-900 dark:text-white placeholder-gray-400 outline-none text-sm">' +
                    '<kbd class="hidden sm:inline-flex items-center px-2 py-0.5 text-xs text-gray-400 bg-gray-100 dark:bg-gray-700 rounded">ESC</kbd>' +
                '</div>' +
                '<div id="cmdPaletteResults" class="max-h-72 overflow-y-auto py-2"></div>' +
                '<div class="px-4 py-2 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between text-xs text-gray-400">' +
                    '<div><kbd class="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded mr-1">&uarr;&darr;</kbd> navigate <kbd class="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded mx-1">&crarr;</kbd> select</div>' +
                    '<div><kbd class="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">esc</kbd> close</div>' +
                '</div>' +
            '</div>';
        document.body.appendChild(div);
        paletteEl = div;
        inputEl = document.getElementById('cmdPaletteInput');
        resultsEl = document.getElementById('cmdPaletteResults');

        // Event listeners
        document.getElementById('cmdPaletteOverlay').addEventListener('click', closePalette);
        inputEl.addEventListener('input', onSearch);
        inputEl.addEventListener('keydown', onKeyDown);
    }

    function openPalette() {
        if (!paletteEl) createPaletteHTML();
        paletteEl.classList.remove('hidden');
        inputEl.value = '';
        selectedIndex = 0;
        onSearch();
        // Delay focus to ensure visible
        setTimeout(function() { inputEl.focus(); }, 50);
        // Prefetch certs if not cached
        if (!certCache) fetchCerts();
    }

    function closePalette() {
        if (paletteEl) paletteEl.classList.add('hidden');
    }

    function isOpen() {
        return paletteEl && !paletteEl.classList.contains('hidden');
    }

    function fetchCerts() {
        fetch('/api/certificates', { credentials: 'same-origin' })
            .then(function(r) { return r.ok ? r.json() : []; })
            .then(function(certs) {
                if (!Array.isArray(certs)) { certCache = []; return; }
                certCache = certs.map(function(c) {
                    return {
                        type: 'cert',
                        icon: 'fa-lock',
                        label: c.domain,
                        desc: (c.exists ? (c.days_until_expiry > 0 ? c.days_until_expiry + ' days left' : 'Expired') : 'Not found'),
                        url: '/',
                        domain: c.domain
                    };
                });
            })
            .catch(function() { certCache = []; });
    }

    function onSearch() {
        var query = (inputEl.value || '').toLowerCase().trim();
        var allItems = staticItems.slice();
        if (certCache) allItems = allItems.concat(certCache);

        if (!query) {
            currentResults = allItems.slice(0, 8);
        } else {
            currentResults = allItems.filter(function(item) {
                return item.label.toLowerCase().indexOf(query) !== -1 ||
                       (item.desc && item.desc.toLowerCase().indexOf(query) !== -1);
            }).slice(0, 10);
        }

        selectedIndex = 0;
        renderResults();
    }

    function renderResults() {
        if (currentResults.length === 0) {
            resultsEl.innerHTML = '<div class="px-4 py-6 text-center text-sm text-gray-500 dark:text-gray-400"><i class="fas fa-search mr-2"></i>No results found</div>';
            return;
        }

        var typeLabels = { nav: 'Navigation', settings: 'Settings', action: 'Actions', cert: 'Certificates' };
        var lastType = '';
        var html = '';

        currentResults.forEach(function(item, i) {
            if (item.type !== lastType) {
                lastType = item.type;
                html += '<div class="px-4 pt-2 pb-1 text-[10px] font-semibold text-gray-400 uppercase tracking-wider">' + escapeHtml(typeLabels[item.type] || item.type) + '</div>';
            }
            var isSelected = i === selectedIndex;
            html += '<div class="cmd-result flex items-center px-4 py-2 cursor-pointer ' +
                (isSelected ? 'bg-primary/10 text-primary' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700/50') +
                '" data-index="' + i + '">' +
                '<i class="fas ' + escapeHtml(item.icon) + ' w-5 text-center mr-3 ' + (isSelected ? 'text-primary' : 'text-gray-400') + '"></i>' +
                '<div class="flex-1 min-w-0">' +
                    '<div class="text-sm font-medium truncate">' + escapeHtml(item.label) + '</div>' +
                    (item.desc ? '<div class="text-xs text-gray-400 truncate">' + escapeHtml(item.desc) + '</div>' : '') +
                '</div>' +
                (item.type === 'action' ? '<i class="fas fa-bolt text-xs text-gray-400 ml-2"></i>' : '<i class="fas fa-arrow-right text-xs text-gray-400 ml-2"></i>') +
            '</div>';
        });

        resultsEl.innerHTML = html;

        // Click handlers on result items
        resultsEl.querySelectorAll('.cmd-result').forEach(function(el) {
            el.addEventListener('click', function() {
                selectItem(parseInt(el.dataset.index));
            });
        });
    }

    function selectItem(index) {
        var item = currentResults[index];
        if (!item) return;
        closePalette();

        if (item.action === 'toggleTheme') {
            if (typeof toggleTheme === 'function') toggleTheme();
            return;
        }
        if (item.action === 'toggleNotifs') {
            if (typeof toggleNotifications === 'function') toggleNotifications();
            return;
        }
        if (item.action === 'focusCreate') {
            window.location.href = item.url;
            setTimeout(function() {
                var el = document.getElementById('domain');
                if (el) el.focus();
            }, 300);
            return;
        }
        if (item.url) {
            window.location.href = item.url;
        }
    }

    function onKeyDown(e) {
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            selectedIndex = Math.min(selectedIndex + 1, currentResults.length - 1);
            renderResults();
            scrollToSelected();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            selectedIndex = Math.max(selectedIndex - 1, 0);
            renderResults();
            scrollToSelected();
        } else if (e.key === 'Enter') {
            e.preventDefault();
            selectItem(selectedIndex);
        } else if (e.key === 'Escape') {
            e.preventDefault();
            closePalette();
        }
    }

    function scrollToSelected() {
        var selected = resultsEl.querySelector('.cmd-result[data-index="' + selectedIndex + '"]');
        if (selected) selected.scrollIntoView({ block: 'nearest' });
    }

    // Global keyboard shortcut: Cmd+K / Ctrl+K
    document.addEventListener('keydown', function(e) {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            if (isOpen()) {
                closePalette();
            } else {
                openPalette();
            }
        }
        if (e.key === 'Escape' && isOpen()) {
            closePalette();
        }
    });
})();
