/**
 * @file
 * Handles the FIDO2/WebAuthn passkey registration ceremony on the
 * "Manage Passkeys" form (/user/{uid}/passkeys/register).
 *
 * Flow:
 *   1. User clicks "Register new passkey".
 *   2. JS fetches PublicKeyCredentialCreationOptions from the challenge endpoint.
 *   3. The options are decoded (base64url → ArrayBuffer) and passed to
 *      navigator.credentials.create().
 *   4. The authenticator response (ArrayBuffer fields → base64url) is POSTed
 *      to the complete endpoint.
 *   5. Success/failure feedback is shown inline without a page reload.
 */
(function (Drupal, drupalSettings, once) {
  'use strict';

  /**
   * Decodes a base64url string to an ArrayBuffer.
   *
   * @param {string} base64url
   *   Base64url-encoded string (no padding required).
   * @returns {ArrayBuffer}
   */
  function base64urlToArrayBuffer(base64url) {
    // Convert base64url to base64 by replacing chars and adding padding.
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binary = window.atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Encodes an ArrayBuffer (or Uint8Array) to a base64url string.
   *
   * @param {ArrayBuffer|Uint8Array} buffer
   * @returns {string}
   */
  function arrayBufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Transforms the raw PublicKeyCredentialCreationOptions JSON received from
   * the server so that ArrayBuffer-typed fields are decoded from base64url.
   *
   * @param {Object} options
   *   The options object from the server (all binary fields are base64url strings).
   * @returns {PublicKeyCredentialCreationOptions}
   */
  function prepareCreationOptions(options) {
    const prepared = Object.assign({}, options);

    // Required binary fields.
    prepared.challenge = base64urlToArrayBuffer(options.challenge);
    prepared.user = Object.assign({}, options.user, {
      id: base64urlToArrayBuffer(options.user.id),
    });

    // excludeCredentials: each id must be an ArrayBuffer.
    if (Array.isArray(options.excludeCredentials)) {
      prepared.excludeCredentials = options.excludeCredentials.map((cred) =>
        Object.assign({}, cred, { id: base64urlToArrayBuffer(cred.id) })
      );
    }

    return prepared;
  }

  /**
   * Serialises a PublicKeyCredential (registration response) for JSON transport.
   *
   * ArrayBuffer fields are base64url-encoded. The response also includes the
   * user-provided label and the transport list if available.
   *
   * @param {PublicKeyCredential} credential
   *   The credential returned by navigator.credentials.create().
   * @param {string} label
   *   User-provided label for the credential.
   * @returns {Object}
   */
  function serializeCredential(credential, label) {
    const response = credential.response;
    const serialized = {
      id: credential.id,
      rawId: arrayBufferToBase64url(credential.rawId),
      type: credential.type,
      label: label || '',
      response: {
        clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
        attestationObject: arrayBufferToBase64url(response.attestationObject),
      },
    };

    // Include transport hints if available (WebAuthn Level 3).
    if (typeof response.getTransports === 'function') {
      serialized.response.transports = response.getTransports();
    }

    return serialized;
  }

  /**
   * Shows a status message in the registration status div.
   *
   * @param {HTMLElement} statusEl
   *   The status container element.
   * @param {string} message
   *   The message to display.
   * @param {'success'|'error'|'info'} type
   *   Message type for CSS class application.
   */
  function showStatus(statusEl, message, type) {
    statusEl.textContent = message;
    statusEl.className = 'passkey-status passkey-status--' + type;
    statusEl.setAttribute('role', 'alert');
  }

  /**
   * Drupal behavior: attaches the passkey registration handler.
   */
  Drupal.behaviors.passkeyRegister = {
    attach(context) {
      const settings = drupalSettings.passkeyForge || {};
      const challengeUrl = settings.challengeUrl;
      const completeUrl = settings.completeUrl;

      if (!challengeUrl || !completeUrl) {
        return;
      }

      // Use once() to prevent duplicate event listeners on re-attach.
      once('passkey-register', '#passkey-register-btn', context).forEach((btn) => {
        btn.addEventListener('click', async (e) => {
          e.preventDefault();

          const statusEl = document.getElementById('passkey-register-status');
          const labelEl = document.getElementById('passkey-label');

          if (!statusEl) {
            return;
          }

          // Check for WebAuthn support.
          if (!window.PublicKeyCredential) {
            showStatus(statusEl, Drupal.t('Your browser does not support passkeys. Please use a modern browser.'), 'error');
            return;
          }

          btn.disabled = true;
          showStatus(statusEl, Drupal.t('Contacting authenticator…'), 'info');

          let options;
          try {
            const challengeResponse = await fetch(challengeUrl, {
              method: 'GET',
              credentials: 'same-origin',
              headers: { 'Accept': 'application/json' },
            });

            if (!challengeResponse.ok) {
              const err = await challengeResponse.json().catch(() => ({}));
              throw new Error(err.error || Drupal.t('Failed to fetch registration options (HTTP @code).', { '@code': challengeResponse.status }));
            }

            options = await challengeResponse.json();
          } catch (err) {
            showStatus(statusEl, Drupal.t('Could not start registration: @msg', { '@msg': err.message }), 'error');
            btn.disabled = false;
            return;
          }

          let credential;
          try {
            const creationOptions = prepareCreationOptions(options);
            credential = await navigator.credentials.create({ publicKey: creationOptions });
          } catch (err) {
            if (err.name === 'NotAllowedError') {
              showStatus(statusEl, Drupal.t('Registration was cancelled or timed out.'), 'error');
            } else if (err.name === 'InvalidStateError') {
              showStatus(statusEl, Drupal.t('This authenticator is already registered.'), 'error');
            } else {
              showStatus(statusEl, Drupal.t('Authenticator error: @msg', { '@msg': err.message }), 'error');
            }
            btn.disabled = false;
            return;
          }

          const label = labelEl ? labelEl.value.trim() : '';

          let result;
          try {
            const completeResponse = await fetch(completeUrl, {
              method: 'POST',
              credentials: 'same-origin',
              headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
              },
              body: JSON.stringify(serializeCredential(credential, label)),
            });

            result = await completeResponse.json();

            if (!completeResponse.ok || !result.success) {
              throw new Error(result.error || Drupal.t('Registration failed (HTTP @code).', { '@code': completeResponse.status }));
            }
          } catch (err) {
            showStatus(statusEl, Drupal.t('Could not complete registration: @msg', { '@msg': err.message }), 'error');
            btn.disabled = false;
            return;
          }

          showStatus(statusEl, Drupal.t('Passkey registered successfully! Refreshing…'), 'success');

          // Reload the page after a short delay so the new credential appears
          // in the credentials table.
          setTimeout(() => {
            window.location.reload();
          }, 1500);
        });
      });
    },
  };

}(Drupal, drupalSettings, once));
