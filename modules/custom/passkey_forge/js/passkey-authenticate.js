/**
 * @file
 * Handles the FIDO2/WebAuthn passkey authentication ceremony on the
 * standard Drupal login form and a dedicated passkey login page.
 *
 * Flow:
 *   1. Page loads; if the user has typed a username the JS fetches challenge
 *      options with ?username= to get the allowCredentials list.
 *      If the site uses discoverable keys (no username required), the challenge
 *      is fetched without a username and allowCredentials is empty.
 *   2. User clicks "Sign in with passkey" button.
 *   3. JS decodes the options and calls navigator.credentials.get().
 *   4. The assertion is encoded (ArrayBuffer → base64url) and POSTed.
 *   5. On success the server returns a redirect URL; the JS navigates there.
 *
 * The module attaches this behaviour on the standard user login form by
 * injecting a "Sign in with passkey" button above the password field when
 * the drupalSettings.passkeyForge.authEnabled flag is set.
 */
(function (Drupal, drupalSettings, once) {
  'use strict';

  /**
   * Decodes a base64url string to an ArrayBuffer.
   *
   * @param {string} base64url
   * @returns {ArrayBuffer}
   */
  function base64urlToArrayBuffer(base64url) {
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
   * Encodes an ArrayBuffer to a base64url string.
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
   * Decodes server-supplied PublicKeyCredentialRequestOptions, converting
   * base64url strings to ArrayBuffers for the WebAuthn API.
   *
   * @param {Object} options
   * @returns {PublicKeyCredentialRequestOptions}
   */
  function prepareRequestOptions(options) {
    const prepared = Object.assign({}, options);
    prepared.challenge = base64urlToArrayBuffer(options.challenge);

    if (Array.isArray(options.allowCredentials)) {
      prepared.allowCredentials = options.allowCredentials.map((cred) =>
        Object.assign({}, cred, { id: base64urlToArrayBuffer(cred.id) })
      );
    }

    return prepared;
  }

  /**
   * Serialises a PublicKeyCredential (authentication assertion) for JSON.
   *
   * @param {PublicKeyCredential} assertion
   * @returns {Object}
   */
  function serializeAssertion(assertion) {
    const response = assertion.response;
    return {
      id: assertion.id,
      rawId: arrayBufferToBase64url(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
        authenticatorData: arrayBufferToBase64url(response.authenticatorData),
        signature: arrayBufferToBase64url(response.signature),
        userHandle: response.userHandle
          ? arrayBufferToBase64url(response.userHandle)
          : null,
      },
    };
  }

  /**
   * Shows or updates an inline status message near the passkey button.
   *
   * @param {HTMLElement} container
   * @param {string} message
   * @param {'info'|'success'|'error'} type
   */
  function showStatus(container, message, type) {
    container.textContent = message;
    container.className = 'passkey-auth-status passkey-auth-status--' + type;
    container.setAttribute('role', 'alert');
    container.removeAttribute('hidden');
  }

  /**
   * Performs the full passkey authentication ceremony.
   *
   * @param {string} challengeUrl
   *   URL of the challenge endpoint.
   * @param {string} completeUrl
   *   URL of the complete (assertion verification) endpoint.
   * @param {string|null} username
   *   Optional username to scope the allowCredentials list.
   * @param {HTMLElement} statusEl
   *   Element to display status messages in.
   * @param {HTMLButtonElement} btn
   *   The triggering button (disabled during ceremony).
   * @param {string} destination
   *   Redirect path after successful login.
   */
  async function performAuthentication(challengeUrl, completeUrl, username, statusEl, btn, destination) {
    btn.disabled = true;
    showStatus(statusEl, Drupal.t('Waiting for authenticator…'), 'info');

    // Step 1: fetch challenge.
    let options;
    try {
      const url = username
        ? challengeUrl + '?username=' + encodeURIComponent(username)
        : challengeUrl;

      const challengeResponse = await fetch(url, {
        method: 'GET',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json' },
      });

      if (!challengeResponse.ok) {
        const err = await challengeResponse.json().catch(() => ({}));
        throw new Error(err.error || Drupal.t('Could not fetch authentication options (HTTP @code).', { '@code': challengeResponse.status }));
      }

      options = await challengeResponse.json();
    } catch (err) {
      showStatus(statusEl, Drupal.t('Could not start authentication: @msg', { '@msg': err.message }), 'error');
      btn.disabled = false;
      return;
    }

    // Step 2: invoke authenticator.
    let assertion;
    try {
      const requestOptions = prepareRequestOptions(options);
      assertion = await navigator.credentials.get({ publicKey: requestOptions });
    } catch (err) {
      if (err.name === 'NotAllowedError') {
        showStatus(statusEl, Drupal.t('Authentication was cancelled or timed out.'), 'error');
      } else {
        showStatus(statusEl, Drupal.t('Authenticator error: @msg', { '@msg': err.message }), 'error');
      }
      btn.disabled = false;
      return;
    }

    // Step 3: send assertion to server.
    let result;
    try {
      const completeUrl2 = destination
        ? completeUrl + '?destination=' + encodeURIComponent(destination)
        : completeUrl;

      const completeResponse = await fetch(completeUrl2, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: JSON.stringify(serializeAssertion(assertion)),
      });

      result = await completeResponse.json();

      if (!completeResponse.ok || !result.success) {
        throw new Error(result.error || Drupal.t('Authentication failed (HTTP @code).', { '@code': completeResponse.status }));
      }
    } catch (err) {
      showStatus(statusEl, Drupal.t('Could not complete sign-in: @msg', { '@msg': err.message }), 'error');
      btn.disabled = false;
      return;
    }

    // Step 4: redirect.
    showStatus(statusEl, Drupal.t('Signed in! Redirecting…'), 'success');
    window.location.href = result.redirect || destination || '/user';
  }

  /**
   * Drupal behavior: attach passkey authentication button to the login form.
   *
   * Injects a "Sign in with passkey" button immediately above the password
   * field on the standard user login form when WebAuthn is available.
   */
  Drupal.behaviors.passkeyAuthenticate = {
    attach(context) {
      const settings = drupalSettings.passkeyForge || {};
      const challengeUrl = settings.authChallengeUrl;
      const completeUrl = settings.authCompleteUrl;

      if (!challengeUrl || !completeUrl) {
        return;
      }

      // Check for browser WebAuthn support.
      if (!window.PublicKeyCredential) {
        return;
      }

      // Attach to existing dedicated passkey login buttons.
      once('passkey-auth-btn', '.passkey-login-button', context).forEach((btn) => {
        const wrapper = btn.closest('.passkey-auth-wrapper') || btn.parentElement;
        let statusEl = wrapper.querySelector('.passkey-auth-status');

        if (!statusEl) {
          statusEl = document.createElement('div');
          statusEl.className = 'passkey-auth-status';
          statusEl.setAttribute('hidden', '');
          wrapper.appendChild(statusEl);
        }

        btn.addEventListener('click', async (e) => {
          e.preventDefault();

          const usernameInput = document.getElementById('edit-name') || document.querySelector('[name="name"]');
          const username = usernameInput ? usernameInput.value.trim() : '';
          const destination = settings.loginDestination || '/user';

          await performAuthentication(challengeUrl, completeUrl, username || null, statusEl, btn, destination);
        });
      });

      // Inject a passkey button into the standard Drupal user login form.
      once('passkey-login-inject', '#user-login-form, .user-login-form', context).forEach((loginForm) => {
        if (!window.PublicKeyCredential) {
          return;
        }

        const passwordWrapper = loginForm.querySelector('.js-form-item-pass') || loginForm.querySelector('[data-drupal-selector="edit-pass"]');
        if (!passwordWrapper) {
          return;
        }

        const wrapper = document.createElement('div');
        wrapper.className = 'passkey-auth-wrapper form-item';

        const passkeyBtn = document.createElement('button');
        passkeyBtn.type = 'button';
        passkeyBtn.className = 'button passkey-login-button';
        passkeyBtn.textContent = Drupal.t('Sign in with passkey');
        passkeyBtn.setAttribute('aria-describedby', 'passkey-auth-hint');

        const hint = document.createElement('small');
        hint.id = 'passkey-auth-hint';
        hint.className = 'passkey-auth-hint';
        hint.textContent = Drupal.t('Use your fingerprint, face, or security key instead of a password.');

        const statusEl = document.createElement('div');
        statusEl.className = 'passkey-auth-status';
        statusEl.setAttribute('hidden', '');

        wrapper.appendChild(passkeyBtn);
        wrapper.appendChild(hint);
        wrapper.appendChild(statusEl);

        passwordWrapper.parentElement.insertBefore(wrapper, passwordWrapper);

        passkeyBtn.addEventListener('click', async (e) => {
          e.preventDefault();

          const usernameInput = loginForm.querySelector('#edit-name, [name="name"]');
          const username = usernameInput ? usernameInput.value.trim() : '';
          const destination = settings.loginDestination || '/user';

          await performAuthentication(challengeUrl, completeUrl, username || null, statusEl, passkeyBtn, destination);
        });
      });
    },
  };

}(Drupal, drupalSettings, once));
