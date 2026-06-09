/**
 * @file
 * Auto-refresh logic for the API Flood Guard flood state dashboard.
 *
 * Polls the flood state data endpoint every 30 seconds (configurable via
 * drupalSettings.apiFloodGuard.pollInterval) and updates the table body
 * without a full page reload.
 */

(function (Drupal, drupalSettings) {
  'use strict';

  Drupal.behaviors.apiFloodGuardStateRefresh = {
    attach: function (context, settings) {
      const table = context.querySelector('[data-flood-state-table]');
      if (!table) {
        return;
      }

      // Avoid attaching multiple times.
      if (table.dataset.floodStateRefreshAttached) {
        return;
      }
      table.dataset.floodStateRefreshAttached = 'true';

      const pollInterval = (settings.apiFloodGuard && settings.apiFloodGuard.pollInterval)
        ? parseInt(settings.apiFloodGuard.pollInterval, 10)
        : 30000;

      const dataUrl = (settings.apiFloodGuard && settings.apiFloodGuard.dataUrl)
        ? settings.apiFloodGuard.dataUrl
        : '/admin/config/security/api-flood-guard/flood-state/data';

      const statusEl = context.querySelector('[data-flood-state-status]');

      function updateTimestamp() {
        if (statusEl) {
          const now = new Date();
          statusEl.textContent = 'Last updated: ' + now.toLocaleTimeString();
        }
      }

      function refreshTable() {
        fetch(dataUrl + '?_format=json', {
          credentials: 'same-origin',
          headers: { 'Accept': 'application/json' }
        })
          .then(function (response) {
            if (!response.ok) {
              throw new Error('HTTP ' + response.status);
            }
            return response.json();
          })
          .then(function (data) {
            const tbody = table.querySelector('tbody');
            if (!tbody) {
              return;
            }

            if (!data.entries || data.entries.length === 0) {
              tbody.innerHTML = '<tr><td colspan="5">' + Drupal.t('No active API flood entries.') + '</td></tr>';
              updateTimestamp();
              return;
            }

            const rows = data.entries.map(function (entry) {
              return '<tr>' +
                '<td>' + escapeHtml(String(entry.fid)) + '</td>' +
                '<td>' + escapeHtml(entry.event) + '</td>' +
                '<td>' + escapeHtml(entry.identifier) + '</td>' +
                '<td>' + escapeHtml(entry.expiration) + ' (' + escapeHtml(String(entry.remaining)) + 's remaining)</td>' +
                '<td><em>' + Drupal.t('Reload page to clear') + '</em></td>' +
                '</tr>';
            });

            tbody.innerHTML = rows.join('');
            updateTimestamp();
          })
          .catch(function (err) {
            if (statusEl) {
              statusEl.textContent = 'Refresh error: ' + err.message;
            }
          });
      }

      /**
       * Escapes HTML special characters to prevent XSS.
       */
      function escapeHtml(text) {
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(text));
        return div.innerHTML;
      }

      // Start the polling interval.
      setInterval(refreshTable, pollInterval);

      updateTimestamp();
    }
  };

})(Drupal, drupalSettings);
