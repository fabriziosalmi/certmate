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
            init: function () {
                var self = this;
                this.$watch('tab', function (tab) { history.replaceState(null, '', '#' + tab); });
                window.addEventListener('hashchange', function () { self.tab = fromHash(); });
            },
            // WAI-ARIA tabs: the arrow keys, Home and End. See settings.js.
            onSettingsTabKeydown: function (event) { window.onSettingsTabKeydown(event); }
        };
    }

    window.settingsTabs = settingsTabs;
    document.addEventListener('alpine:init', function () {
        Alpine.data('settingsTabs', settingsTabs);
    });
})();
