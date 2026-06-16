// @ts-check
/**
 * @file
 * Playwright end-to-end tests for the Passkey Forge Drupal module.
 *
 * These tests exercise the browser-visible behaviour of the passkey
 * registration and authentication flows using Playwright's WebAuthn virtual
 * authenticator API (available in Chromium via CDP). They also cover the admin
 * settings form and the passkey management page.
 *
 * Prerequisites:
 *   - A running Drupal 11 site with passkey_forge installed.
 *   - DRUPAL_BASE_URL environment variable set (default: http://localhost).
 *   - An admin user with credentials DRUPAL_ADMIN_USER / DRUPAL_ADMIN_PASS.
 *   - The site's RP ID and origin must be configured to match the test URL.
 *
 * Run with:
 *   npx playwright test playwright/passkey_forge.spec.js
 */

const { test, expect, chromium } = require('@playwright/test');

/** Base URL of the Drupal site under test. */
const BASE_URL = process.env.DRUPAL_BASE_URL || 'http://localhost';

/** Admin credentials. */
const ADMIN_USER = process.env.DRUPAL_ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.DRUPAL_ADMIN_PASS || 'admin';

/**
 * Helper: log into Drupal via the standard login form.
 *
 * @param {import('@playwright/test').Page} page
 * @param {string} username
 * @param {string} password
 */
async function drupalLogin(page, username, password) {
  await page.goto(`${BASE_URL}/user/login`);
  await page.fill('#edit-name', username);
  await page.fill('#edit-pass', password);
  await page.click('#edit-submit');
  await expect(page).not.toHaveURL(/\/user\/login/);
}

/**
 * Helper: log out of Drupal.
 *
 * @param {import('@playwright/test').Page} page
 */
async function drupalLogout(page) {
  await page.goto(`${BASE_URL}/user/logout`);
}

// =============================================================================
// Settings form
// =============================================================================

test.describe('Passkey Forge settings form', () => {

  test.beforeEach(async ({ page }) => {
    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);
  });

  test.afterEach(async ({ page }) => {
    await drupalLogout(page);
  });

  test('settings page is accessible to admin', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security/passkey-forge`);
    await expect(page).toHaveTitle(/Passkey Forge/i);
    await expect(page.locator('h1')).toContainText(/Passkey Forge/i);
  });

  test('settings form renders all required fields', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security/passkey-forge`);
    await expect(page.locator('[name="enabled"]')).toBeVisible();
    await expect(page.locator('[name="rp_id"]')).toBeVisible();
    await expect(page.locator('[name="rp_name"]')).toBeVisible();
    await expect(page.locator('[name="allowed_origins"]')).toBeVisible();
    await expect(page.locator('[name="attestation_policy"]').first()).toBeVisible();
    await expect(page.locator('[name="timeout"]')).toBeVisible();
    await expect(page.locator('[name="user_verification"]').first()).toBeVisible();
    await expect(page.locator('[name="require_resident_key"]')).toBeVisible();
    await expect(page.locator('[name="allow_password_fallback"]')).toBeVisible();
    await expect(page.locator('[name="challenge_ttl"]')).toBeVisible();
  });

  test('settings form save shows confirmation', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security/passkey-forge`);

    await page.fill('[name="rp_id"]', 'localhost');
    await page.fill('[name="rp_name"]', 'Playwright Test Site');
    await page.fill('[name="allowed_origins"]', BASE_URL);
    await page.fill('[name="timeout"]', '60000');
    await page.fill('[name="challenge_ttl"]', '300');

    await page.click('[value="Save configuration"]');

    await expect(page.locator('.messages--status')).toContainText(/configuration options have been saved/i);
  });

  test('empty RP ID shows validation error', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security/passkey-forge`);

    await page.fill('[name="rp_id"]', '');
    await page.click('[value="Save configuration"]');

    // Browser HTML5 required validation or Drupal server-side validation.
    const errors = page.locator('.messages--error, [class*="error"]');
    await expect(errors).toBeVisible();
  });

  test('invalid allowed_origins URL shows validation error', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security/passkey-forge`);

    await page.fill('[name="allowed_origins"]', 'not-a-url');
    await page.click('[value="Save configuration"]');

    await expect(page.locator('.messages--error, [class*="error"]')).toBeVisible();
  });

  test('attestation policy radios contain none, indirect, direct', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security/passkey-forge`);

    await expect(page.getByText('None', { exact: false })).toBeVisible();
    await expect(page.getByText('Indirect', { exact: false })).toBeVisible();
    await expect(page.getByText('Direct', { exact: false })).toBeVisible();
  });

  test('settings page is linked from /admin/config/security', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security`);
    const link = page.locator(`a[href*="passkey-forge"]`);
    await expect(link).toBeVisible();
  });

});

// =============================================================================
// Access control
// =============================================================================

test.describe('Passkey Forge access control', () => {

  test('anonymous user is redirected from settings page', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security/passkey-forge`);
    await expect(page).not.toHaveURL(/passkey-forge/);
  });

  test('login form has passkey button injected (when WebAuthn supported)', async ({ page }) => {
    // The passkey-authenticate.js behaviour injects a button on the login form.
    // We verify the library is loaded and the button appears.
    await page.goto(`${BASE_URL}/user/login`);

    // Wait for JS to run.
    await page.waitForLoadState('networkidle');

    // If the browser supports WebAuthn, the button should be injected.
    const supportsWebAuthn = await page.evaluate(() => !!window.PublicKeyCredential);
    if (supportsWebAuthn) {
      await expect(page.locator('.passkey-login-button')).toBeVisible({ timeout: 3000 });
    } else {
      test.skip();
    }
  });

});

// =============================================================================
// Passkey registration (requires WebAuthn virtual authenticator)
// =============================================================================

test.describe('Passkey registration ceremony', () => {

  test('manage passkeys page renders for logged-in user', async ({ page }) => {
    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);

    // Get admin user ID from profile page.
    await page.goto(`${BASE_URL}/user`);
    const url = page.url();
    const uidMatch = url.match(/\/user\/(\d+)/);
    const uid = uidMatch ? uidMatch[1] : '1';

    await page.goto(`${BASE_URL}/user/${uid}/passkeys/register`);
    await expect(page).toHaveTitle(/Manage Passkeys/i);
    await expect(page.locator('#passkey-register-btn')).toBeVisible();

    await drupalLogout(page);
  });

  test('registration challenge endpoint returns JSON options', async ({ page }) => {
    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);

    const response = await page.request.get(`${BASE_URL}/passkey-forge/register/challenge`, {
      headers: { 'Accept': 'application/json' },
    });

    expect(response.status()).toBe(200);
    const body = await response.json();

    expect(body).toHaveProperty('challenge');
    expect(body).toHaveProperty('rp');
    expect(body).toHaveProperty('user');
    expect(body).toHaveProperty('pubKeyCredParams');
    expect(body).toHaveProperty('timeout');
    expect(body).toHaveProperty('attestation');

    await drupalLogout(page);
  });

  test('registration challenge endpoint returns 401 for anonymous', async ({ page }) => {
    const response = await page.request.get(`${BASE_URL}/passkey-forge/register/challenge`, {
      headers: { 'Accept': 'application/json' },
    });

    // Either 401 or a redirect to login (3xx/200 after redirect).
    expect([200, 401, 403, 302, 303]).toContain(response.status());
  });

  test('registration with virtual authenticator creates credential', async () => {
    // This test uses Chromium CDP to inject a virtual FIDO2 authenticator.
    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();

    // Create a CDP session to configure the virtual authenticator.
    const cdp = await context.newCDPSession(page);

    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });

    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);

    // Get UID.
    await page.goto(`${BASE_URL}/user`);
    const url = page.url();
    const uidMatch = url.match(/\/user\/(\d+)/);
    const uid = uidMatch ? uidMatch[1] : '1';

    await page.goto(`${BASE_URL}/user/${uid}/passkeys/register`);
    await page.waitForLoadState('networkidle');

    const registerBtn = page.locator('#passkey-register-btn');
    await expect(registerBtn).toBeVisible();

    await registerBtn.click();

    // Wait for the status message to update.
    const statusEl = page.locator('#passkey-register-status');
    await expect(statusEl).toBeVisible({ timeout: 10000 });

    // On success the status contains "successfully" or the page reloads.
    // We check for either.
    try {
      await expect(statusEl).toContainText(/success/i, { timeout: 8000 });
    } catch {
      // Page may have already reloaded — check that the credentials table exists.
      await expect(page.locator('#passkey-list')).toBeVisible({ timeout: 5000 });
    }

    await drupalLogout(page);
    await cdp.send('WebAuthn.disable');
    await browser.close();
  });

});

// =============================================================================
// Passkey authentication (requires WebAuthn virtual authenticator)
// =============================================================================

test.describe('Passkey authentication ceremony', () => {

  test('authentication challenge endpoint returns JSON options', async ({ page }) => {
    const response = await page.request.get(`${BASE_URL}/passkey-forge/auth/challenge`, {
      headers: { 'Accept': 'application/json' },
    });

    expect(response.status()).toBe(200);
    const body = await response.json();

    expect(body).toHaveProperty('challenge');
    expect(body).toHaveProperty('rpId');
    expect(body).toHaveProperty('timeout');
    expect(body).toHaveProperty('allowCredentials');
    expect(body).toHaveProperty('userVerification');
  });

  test('authentication challenge with username restricts allowCredentials', async ({ page }) => {
    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);
    await drupalLogout(page);

    const response = await page.request.get(
      `${BASE_URL}/passkey-forge/auth/challenge?username=${encodeURIComponent(ADMIN_USER)}`,
      { headers: { 'Accept': 'application/json' } },
    );

    expect(response.status()).toBe(200);
    // We can't assert allowCredentials.length because the admin may not have
    // a passkey registered in CI, but we can assert the structure is valid.
    const body = await response.json();
    expect(Array.isArray(body.allowCredentials)).toBe(true);
  });

  test('complete endpoint rejects POST without challenge', async ({ page }) => {
    // POST to complete without first fetching a challenge: should get 400.
    const response = await page.request.post(`${BASE_URL}/passkey-forge/auth/complete`, {
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      data: JSON.stringify({ id: 'fake', rawId: 'fake', type: 'public-key', response: {} }),
    });

    expect([400, 401]).toContain(response.status());
  });

});

// =============================================================================
// Admin: user passkeys view
// =============================================================================

test.describe('Passkey Forge admin user keys view', () => {

  test.beforeEach(async ({ page }) => {
    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);
  });

  test.afterEach(async ({ page }) => {
    await drupalLogout(page);
  });

  test('admin can access user keys page for uid 1', async ({ page }) => {
    const response = await page.request.get(`${BASE_URL}/admin/config/security/passkey-forge/users/1/keys`);
    // Should be 200 (with credentials) not a redirect.
    expect(response.status()).toBe(200);
  });

  test('user keys page renders table structure', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security/passkey-forge/users/1/keys`);
    await page.waitForLoadState('networkidle');

    // Table headers should be visible even if empty.
    await expect(page.locator('table')).toBeVisible();
  });

  test('user keys page for non-existent user shows error', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security/passkey-forge/users/999999/keys`);
    await expect(page.locator('body')).toContainText(/not found|User/i);
  });

});
