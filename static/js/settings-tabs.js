(function () {
    'use strict';

    // The Settings page's one Alpine root: which tab is showing, kept in the
    // URL's fragment in both directions. It was written out in the template,
    // with `location`, `history` and `window` in the expression; the build of
    // Alpine in use evaluates an expression without `eval` and reaches none of
    // those from one.
    //
    // In a file of its own, loaded after settings.js (which defines the
    // keyboard handler), so that it can be read without running that file:
    // scripts/check_alpine_expressions.mjs loads every file that registers a
    // component to learn the names a template may use.
    function settingsTabs() {
        function fromHash() {
            return location.hash.slice(1) || 'general';
        }
        return {
            tab: fromHash(),
            // The side menu's groups, and the phone's list (#1423). The ids are the panels'
            // (`settings-panel-<id>`) and the URL fragment's.
            sectionGroups: [
                { id: 'certificates', label: 'Certificates', tabs: [
                    { id: 'general', icon: 'fa-cogs', label: 'General' },
                    { id: 'dns', icon: 'fa-server', label: 'DNS' },
                    { id: 'ca', icon: 'fa-shield-alt', label: 'CA' },
                    { id: 'storage', icon: 'fa-database', label: 'Storage' },
                    { id: 'deploy', icon: 'fa-rocket', label: 'Deploy' },
                    { id: 'probe', icon: 'fa-network-wired', label: 'Probe' },
                    { id: 'acme', icon: 'fa-certificate', label: 'ACME' }
                ] },
                { id: 'access', label: 'Access', tabs: [
                    { id: 'users', icon: 'fa-users', label: 'Users' },
                    { id: 'apikeys', icon: 'fa-key', label: 'API Keys' },
                    { id: 'oidc', icon: 'fa-id-badge', label: 'SSO' }
                ] },
                { id: 'system', label: 'System', tabs: [
                    { id: 'notifications', icon: 'fa-bell', label: 'Notifications' },
                    { id: 'backup', icon: 'fa-archive', label: 'Backup' }
                ] }
            ],
            init: function () {
                var self = this;
                this.$watch('tab', function (tab) { history.replaceState(null, '', '#' + tab); });
                window.addEventListener('hashchange', function () { self.tab = fromHash(); });
            },
            // WAI-ARIA tabs: the arrow keys, Home and End, across the groups. See settings.js.
            onSettingsTabKeydown: function (event) { window.onSettingsTabKeydown(event); }
        };
    }

    window.settingsTabs = settingsTabs;
    document.addEventListener('alpine:init', function () {
        Alpine.data('settingsTabs', settingsTabs);
    });
})();
