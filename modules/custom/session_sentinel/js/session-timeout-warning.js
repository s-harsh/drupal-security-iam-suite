/**
 * @file
 * Session Sentinel idle-timeout warning banner with countdown.
 *
 * Reads drupalSettings.sessionSentinel.idleTimeout (seconds) and
 * drupalSettings.sessionSentinel.warningLeadTime (seconds) to schedule:
 *
 *   1. A countdown banner that appears `warningLeadTime` seconds before expiry.
 *   2. A forced redirect to the login page when `idleTimeout` seconds have
 *      elapsed since the last user activity recorded on this page.
 *
 * User activity (mousemove, keydown, click, scroll, touchstart) resets the
 * idle timer and sends a lightweight keep-alive AJAX request so the server-side
 * last_active timestamp is also refreshed. Activity reset is throttled to once
 * per 30 seconds to avoid excessive traffic.
 *
 * The "Stay logged in" button in the banner also triggers a keep-alive ping
 * and dismisses the warning.
 */

(function (Drupal, drupalSettings, once) {
  'use strict';

  Drupal.behaviors.sessionSentinelTimeoutWarning = {
    attach: function (context, settings) {
      // Only attach once to the document body.
      const targets = once('session-sentinel-timeout', 'body', context);
      if (targets.length === 0) {
        return;
      }

      const sentinelSettings = settings.sessionSentinel || {};
      const idleTimeout = parseInt(sentinelSettings.idleTimeout, 10) || 0;
      const warningLeadTime = parseInt(sentinelSettings.warningLeadTime, 10) || 300;
      const keepAliveUrl = sentinelSettings.keepAliveUrl || '/session-sentinel/keepalive';
      const logoutUrl = sentinelSettings.logoutUrl || '/user/logout';

      // No timeout configured — nothing to do.
      if (idleTimeout <= 0) {
        return;
      }

      let lastActivityAt = Date.now();
      let warningVisible = false;
      let warningBanner = null;
      let countdownInterval = null;
      let keepAliveThrottleTimer = null;

      /**
       * Records user activity, resets idle timer, sends throttled keep-alive.
       */
      function recordActivity() {
        lastActivityAt = Date.now();

        // Dismiss the warning banner if it was showing.
        if (warningVisible) {
          dismissWarning();
        }

        // Throttled keep-alive: send at most once per 30 seconds.
        if (keepAliveThrottleTimer === null) {
          keepAliveThrottleTimer = setTimeout(function () {
            sendKeepAlive();
            keepAliveThrottleTimer = null;
          }, 30000);
        }
      }

      /**
       * Sends a keep-alive request to refresh the server-side last_active.
       */
      function sendKeepAlive() {
        fetch(keepAliveUrl, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
          },
          body: JSON.stringify({ ts: Math.floor(Date.now() / 1000) }),
        }).catch(function () {
          // Silently swallow keep-alive errors — the session will expire
          // server-side if connectivity is truly lost.
        });
      }

      /**
       * Creates and displays the countdown warning banner.
       *
       * @param {number} secondsLeft Seconds remaining before forced logout.
       */
      function showWarning(secondsLeft) {
        if (warningVisible) {
          return;
        }
        warningVisible = true;

        warningBanner = document.createElement('div');
        warningBanner.id = 'session-sentinel-warning';
        warningBanner.setAttribute('role', 'alert');
        warningBanner.setAttribute('aria-live', 'assertive');
        warningBanner.style.cssText = [
          'position:fixed',
          'top:0',
          'left:0',
          'right:0',
          'z-index:99999',
          'background:#d32f2f',
          'color:#fff',
          'padding:12px 20px',
          'font-size:15px',
          'display:flex',
          'align-items:center',
          'justify-content:space-between',
          'box-shadow:0 2px 8px rgba(0,0,0,.4)',
        ].join(';');

        const messageSpan = document.createElement('span');
        messageSpan.id = 'session-sentinel-countdown-msg';
        messageSpan.textContent = Drupal.t(
          'Your session will expire in @seconds seconds due to inactivity.',
          { '@seconds': secondsLeft }
        );

        const stayBtn = document.createElement('button');
        stayBtn.type = 'button';
        stayBtn.textContent = Drupal.t('Stay logged in');
        stayBtn.style.cssText = [
          'margin-left:16px',
          'padding:6px 14px',
          'background:#fff',
          'color:#d32f2f',
          'border:none',
          'border-radius:3px',
          'cursor:pointer',
          'font-weight:bold',
          'font-size:14px',
        ].join(';');
        stayBtn.addEventListener('click', function () {
          recordActivity();
          sendKeepAlive();
        });

        warningBanner.appendChild(messageSpan);
        warningBanner.appendChild(stayBtn);
        document.body.prepend(warningBanner);

        // Update countdown every second.
        let remaining = secondsLeft;
        countdownInterval = setInterval(function () {
          remaining -= 1;
          if (remaining <= 0) {
            clearInterval(countdownInterval);
            countdownInterval = null;
            return;
          }
          const msg = document.getElementById('session-sentinel-countdown-msg');
          if (msg) {
            msg.textContent = Drupal.t(
              'Your session will expire in @seconds seconds due to inactivity.',
              { '@seconds': remaining }
            );
          }
        }, 1000);
      }

      /**
       * Dismisses the warning banner and clears its countdown.
       */
      function dismissWarning() {
        warningVisible = false;
        if (countdownInterval !== null) {
          clearInterval(countdownInterval);
          countdownInterval = null;
        }
        if (warningBanner && warningBanner.parentNode) {
          warningBanner.parentNode.removeChild(warningBanner);
          warningBanner = null;
        }
      }

      /**
       * Main polling tick: checks elapsed idle time and triggers warning/logout.
       */
      function tick() {
        const idleSeconds = Math.floor((Date.now() - lastActivityAt) / 1000);
        const remaining = idleTimeout - idleSeconds;

        if (remaining <= 0) {
          // Time is up — force a logout redirect.
          window.location.href = logoutUrl + '?destination=user/login&session_expired=1';
          return;
        }

        if (remaining <= warningLeadTime) {
          showWarning(remaining);
        } else {
          if (warningVisible) {
            dismissWarning();
          }
        }
      }

      // Bind activity listeners.
      ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(function (eventName) {
        document.addEventListener(eventName, recordActivity, { passive: true });
      });

      // Poll every second.
      setInterval(tick, 1000);
    }
  };

})(Drupal, drupalSettings, once);
