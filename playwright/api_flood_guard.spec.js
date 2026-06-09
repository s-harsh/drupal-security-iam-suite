// @ts-check
'use strict';

/**
 * @file
 * Playwright end-to-end tests for the API Flood Guard Drupal module.
 *
 * Prerequisites:
 *   - Drupal running at http://localhost (or DRUPAL_BASE_URL env var)
 *   - api_flood_guard module installed and enabled
 *   - An admin account with username "admin" and password "admin"
 *     (or set DRUPAL_ADMIN_USER / DRUPAL_ADMIN_PASS env vars)
 *   - dblog module enabled (for the log page tests)
 *
 * Run:
 *   npx playwright test playwright/api_flood_guard.spec.js
 * Run headed:
 *   npx playwright test playwright/api_flood_guard.spec.js --headed
 */

const { test, expect } = require('@playwright/test');

// ─── Configuration ────────────────────────────────────────────────────────────

const ADMIN_USER = process.env.DRUPAL_ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.DRUPAL_ADMIN_PASS || 'admin';

const SETTINGS_PATH = '/admin/config/security/api-flood-guard';
const FLOOD_STATE_PATH = '/admin/config/security/api-flood-guard/flood-state';
const LOG_PATH = '/admin/config/security/api-flood-guard/log';
const FLOOD_DATA_PATH = '/admin/config/security/api-flood-guard/flood-state/data';

// ─── Shared helpers ────────────────────────────────────────────────────────────

/**
 * Logs in as the configured admin user.
 *
 * @param {import('@playwright/test').Page} page
 */
async function loginAsAdmin(page) {
  await page.goto('/user/login');
  await page.waitForSelector('#edit-name');
  await page.fill('#edit-name', ADMIN_USER);
  await page.fill('#edit-pass', ADMIN_PASS);
  await page.click('#edit-submit');
  // Wait until we are redirected away from the login page.
  await page.waitForURL((url) => !url.pathname.includes('/user/login'), { timeout: 10_000 });
}

/**
 * Fills and submits the settings form with the supplied values.
 *
 * Only the provided keys are filled; existing defaults are preserved for
 * fields that are omitted.
 *
 * @param {import('@playwright/test').Page} page
 * @param {Object} values - Partial map of field name to value.
 */
async function fillAndSubmitSettingsForm(page, values) {
  await page.goto(SETTINGS_PATH);
  await page.waitForSelector('form#api-flood-guard-settings-form, form', { timeout: 10_000 });

  for (const [name, value] of Object.entries(values)) {
    const locator = page.locator(`[name="${name}"]`);
    const count = await locator.count();
    if (count === 0) continue;

    const tagName = await locator.evaluate((el) => el.tagName.toLowerCase());
    const type = await locator.evaluate((el) => el.getAttribute('type') || '');

    if (tagName === 'select') {
      await locator.selectOption(String(value));
    } else if (type === 'checkbox') {
      if (value) {
        await locator.check();
      } else {
        await locator.uncheck();
      }
    } else {
      await locator.fill(String(value));
    }
  }

  await page.click('[value="Save configuration"]');
}

// ─── Test suite ───────────────────────────────────────────────────────────────

test.describe('API Flood Guard — Settings Page', () => {

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('settings page loads with HTTP 200', async ({ page }) => {
    const response = await page.goto(SETTINGS_PATH);
    expect(response.status()).toBe(200);
  });

  test('settings page title contains "API Flood Guard"', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('h1')).toContainText('API Flood Guard');
  });

  test('settings page has the protected paths textarea', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('[name="protected_paths"]')).toBeVisible();
  });

  test('settings page has the ip_threshold field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('[name="ip_threshold"]')).toBeVisible();
  });

  test('settings page has the allowlist textarea', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('[name="allowlist"]')).toBeVisible();
  });

  test('settings page has the response_code select', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('[name="response_code"]')).toBeVisible();
  });

  test('settings page has the block_message field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('[name="block_message"]')).toBeVisible();
  });

  test('can save valid threshold values and see success message', async ({ page }) => {
    await fillAndSubmitSettingsForm(page, {
      ip_threshold: '50',
      ip_window: '1800',
      user_threshold: '10',
      user_window: '600',
      response_code: '429',
      block_message: 'Rate limit exceeded.',
    });

    await expect(
      page.locator('.messages--status, .messages.status, [data-drupal-messages]')
    ).toContainText('The configuration options have been saved.', { timeout: 10_000 });
  });

  test('can save a valid IPv4 CIDR in the allowlist', async ({ page }) => {
    await fillAndSubmitSettingsForm(page, {
      allowlist: '10.0.0.0/8\n127.0.0.1',
    });
    await expect(
      page.locator('.messages--status, .messages.status, [data-drupal-messages]')
    ).toContainText('The configuration options have been saved.', { timeout: 10_000 });
  });

  test('can save a valid IPv6 address in the allowlist', async ({ page }) => {
    await fillAndSubmitSettingsForm(page, {
      allowlist: '::1',
    });
    await expect(
      page.locator('.messages--status, .messages.status, [data-drupal-messages]')
    ).toContainText('The configuration options have been saved.', { timeout: 10_000 });
  });

  test('invalid CIDR in allowlist shows validation error', async ({ page }) => {
    await fillAndSubmitSettingsForm(page, {
      allowlist: '999.999.0.0/8',
    });
    await expect(
      page.locator('.messages--error, .messages.error, [data-drupal-messages]')
    ).toContainText('Invalid IP address or CIDR range', { timeout: 10_000 });
  });

  test('invalid protected path format shows validation error', async ({ page }) => {
    await fillAndSubmitSettingsForm(page, {
      protected_paths: 'invalid-no-colon',
    });
    await expect(
      page.locator('.messages--error, .messages.error, [data-drupal-messages]')
    ).toContainText('Invalid path entry', { timeout: 10_000 });
  });

  test('can save response_code 503', async ({ page }) => {
    await fillAndSubmitSettingsForm(page, {
      response_code: '503',
    });
    await expect(
      page.locator('.messages--status, .messages.status, [data-drupal-messages]')
    ).toContainText('The configuration options have been saved.', { timeout: 10_000 });

    // Restore default.
    await fillAndSubmitSettingsForm(page, { response_code: '429' });
  });

  test('can toggle debug logging checkbox and save', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    const checkbox = page.locator('[name="debug_logging"]');
    const wasChecked = await checkbox.isChecked();

    if (!wasChecked) {
      await checkbox.check();
    } else {
      await checkbox.uncheck();
    }

    await page.click('[value="Save configuration"]');
    await expect(
      page.locator('.messages--status, .messages.status, [data-drupal-messages]')
    ).toContainText('The configuration options have been saved.', { timeout: 10_000 });

    // Restore original state.
    await page.goto(SETTINGS_PATH);
    if (!wasChecked) {
      await page.locator('[name="debug_logging"]').uncheck();
    } else {
      await page.locator('[name="debug_logging"]').check();
    }
    await page.click('[value="Save configuration"]');
  });

});

// ─────────────────────────────────────────────────────────────────────────────

test.describe('API Flood Guard — Flood State Dashboard', () => {

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('flood state page loads with HTTP 200', async ({ page }) => {
    const response = await page.goto(FLOOD_STATE_PATH);
    expect(response.status()).toBe(200);
  });

  test('flood state page title is present', async ({ page }) => {
    await page.goto(FLOOD_STATE_PATH);
    await expect(page.locator('h1')).toBeVisible();
  });

  test('flood state page has the Clear all button', async ({ page }) => {
    await page.goto(FLOOD_STATE_PATH);
    const clearAll = page.locator('[value="Clear all API flood entries"]');
    await expect(clearAll).toBeVisible();
  });

  test('flood state page has the Clear all IP flood entries button', async ({ page }) => {
    await page.goto(FLOOD_STATE_PATH);
    const clearIp = page.locator('[value="Clear all IP flood entries"]');
    await expect(clearIp).toBeVisible();
  });

  test('flood state page has the Clear all username flood entries button', async ({ page }) => {
    await page.goto(FLOOD_STATE_PATH);
    const clearUser = page.locator('[value="Clear all username flood entries"]');
    await expect(clearUser).toBeVisible();
  });

  test('clicking Clear all shows confirmation status message', async ({ page }) => {
    await page.goto(FLOOD_STATE_PATH);
    await page.click('[value="Clear all API flood entries"]');
    await expect(
      page.locator('.messages--status, .messages.status, [data-drupal-messages]')
    ).toContainText('cleared', { timeout: 10_000 });
  });

  test('clicking Clear all IP flood entries shows confirmation message', async ({ page }) => {
    await page.goto(FLOOD_STATE_PATH);
    await page.click('[value="Clear all IP flood entries"]');
    await expect(
      page.locator('.messages--status, .messages.status, [data-drupal-messages]')
    ).toContainText('IP flood entries', { timeout: 10_000 });
  });

  test('clicking Clear all username flood entries shows confirmation message', async ({ page }) => {
    await page.goto(FLOOD_STATE_PATH);
    await page.click('[value="Clear all username flood entries"]');
    await expect(
      page.locator('.messages--status, .messages.status, [data-drupal-messages]')
    ).toContainText('username flood entries', { timeout: 10_000 });
  });

  test('empty state message is visible when there are no flood entries', async ({ page }) => {
    // First clear everything.
    await page.goto(FLOOD_STATE_PATH);
    await page.click('[value="Clear all API flood entries"]');
    await page.goto(FLOOD_STATE_PATH);
    await expect(page.locator('body')).toContainText('No active API flood entries.', { timeout: 5_000 });
  });

});

// ─────────────────────────────────────────────────────────────────────────────

test.describe('API Flood Guard — Block Events Log', () => {

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('log page loads with HTTP 200', async ({ page }) => {
    const response = await page.goto(LOG_PATH);
    expect(response.status()).toBe(200);
  });

  test('log page shows table headers', async ({ page }) => {
    await page.goto(LOG_PATH);
    await expect(page.locator('body')).toContainText('Timestamp');
    await expect(page.locator('body')).toContainText('Severity');
    await expect(page.locator('body')).toContainText('Message');
    await expect(page.locator('body')).toContainText('Hostname');
  });

  test('log page with no entries shows empty message', async ({ page }) => {
    await page.goto(LOG_PATH);
    // Should display the table (even if empty).
    await expect(page.locator('body')).toContainText('No API Flood Guard block events found.');
  });

  test('log page accepts severity filter without error', async ({ page }) => {
    const response = await page.goto(`${LOG_PATH}?severity=4`);
    expect(response.status()).toBe(200);
  });

});

// ─────────────────────────────────────────────────────────────────────────────

test.describe('API Flood Guard — Flood State JSON Endpoint', () => {

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('flood state data endpoint returns HTTP 200', async ({ page }) => {
    const response = await page.goto(FLOOD_DATA_PATH);
    expect(response.status()).toBe(200);
  });

  test('flood state data endpoint returns valid JSON with required keys', async ({ page }) => {
    const response = await page.goto(FLOOD_DATA_PATH);
    const contentType = response.headers()['content-type'] || '';
    expect(contentType).toContain('application/json');

    const body = await response.json();
    expect(body).toHaveProperty('entries');
    expect(body).toHaveProperty('count');
    expect(body).toHaveProperty('timestamp');
    expect(Array.isArray(body.entries)).toBe(true);
    expect(typeof body.count).toBe('number');
    expect(typeof body.timestamp).toBe('number');
  });

  test('flood state data count matches entries array length', async ({ page }) => {
    const response = await page.goto(FLOOD_DATA_PATH);
    const body = await response.json();
    expect(body.count).toBe(body.entries.length);
  });

});

// ─────────────────────────────────────────────────────────────────────────────

test.describe('API Flood Guard — Access Control', () => {

  test('anonymous user is redirected away from settings page', async ({ page }) => {
    const response = await page.goto(SETTINGS_PATH);
    // Either redirect to login (302 → 200 at /user/login) or direct 403.
    const finalUrl = page.url();
    const isLoginPage = finalUrl.includes('/user/login');
    const isAccessDenied = response.status() === 403;
    expect(isLoginPage || isAccessDenied).toBe(true);
  });

  test('anonymous user is redirected away from flood state page', async ({ page }) => {
    await page.goto(FLOOD_STATE_PATH);
    const finalUrl = page.url();
    const isLoginPage = finalUrl.includes('/user/login');
    const statusCode = (await page.evaluate(() => document.title)).toLowerCase();
    // Either redirected to login or shown access denied.
    expect(isLoginPage || statusCode.includes('access denied')).toBe(true);
  });

  test('anonymous user is redirected away from log page', async ({ page }) => {
    await page.goto(LOG_PATH);
    const finalUrl = page.url();
    const isLoginPage = finalUrl.includes('/user/login');
    expect(isLoginPage || !finalUrl.includes(LOG_PATH)).toBe(true);
  });

});

// ─────────────────────────────────────────────────────────────────────────────

test.describe('API Flood Guard — Flood Blocking Behavior', () => {

  /**
   * These tests mutate flood state to trigger blocking.
   * They restore configuration afterwards.
   */
  let savedConfig = null;

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);

    // Lower the threshold to trigger a block easily.
    await fillAndSubmitSettingsForm(page, {
      ip_threshold: '3',
      ip_window: '3600',
      user_threshold: '2',
      user_window: '900',
      response_code: '429',
      block_message: 'Too many authentication requests. Please wait before trying again.',
      allowlist: '',
      protected_paths: 'exact:/user/login\nprefix:/jsonapi',
    });
  });

  test.afterEach(async ({ page }) => {
    // Restore safe defaults so other tests are not affected.
    await fillAndSubmitSettingsForm(page, {
      ip_threshold: '100',
      ip_window: '3600',
      user_threshold: '20',
      user_window: '900',
      response_code: '429',
      allowlist: '',
      protected_paths: 'exact:/user/login\nprefix:/jsonapi\nexact:/oauth/token\nexact:/rest/user/login',
    });

    // Clear all flood entries.
    await page.goto(FLOOD_STATE_PATH);
    await page.click('[value="Clear all API flood entries"]');
  });

  test('exceeding IP threshold returns 429', async ({ page }) => {
    // Make requests to /user/login?_format=json to trigger API flood.
    let lastStatus = 0;
    for (let i = 0; i <= 3; i++) {
      const resp = await page.goto('/user/login?_format=json');
      lastStatus = resp.status();
    }
    expect(lastStatus).toBe(429);
  });

  test('blocked response body contains errors key when JSON accepted', async ({ page }) => {
    // Set Accept header via extra HTTP headers.
    await page.setExtraHTTPHeaders({ Accept: 'application/vnd.api+json' });

    for (let i = 0; i <= 3; i++) {
      await page.goto('/user/login?_format=json');
    }

    const content = await page.content();
    // The raw JSON body is in the page; verify it contains "errors".
    expect(content).toContain('"errors"');

    await page.setExtraHTTPHeaders({});
  });

  test('HTML form GET to /user/login is NOT blocked by API flood guard', async ({ page }) => {
    // GET requests to /user/login should NEVER get a 429 from this module.
    for (let i = 0; i < 6; i++) {
      const resp = await page.goto('/user/login');
      expect(resp.status()).not.toBe(429);
    }
  });

  test('allowlisted IP (127.0.0.1) is never blocked', async ({ page }) => {
    // Add 127.0.0.1 to the allowlist.
    await fillAndSubmitSettingsForm(page, {
      allowlist: '127.0.0.1\n::1',
    });

    // Make many more requests than the threshold.
    let lastStatus = 0;
    for (let i = 0; i < 10; i++) {
      const resp = await page.goto('/user/login?_format=json');
      lastStatus = resp.status();
    }
    // Should NOT be 429 because the test client IP is allowlisted.
    expect(lastStatus).not.toBe(429);
  });

  test('blocked response has Retry-After header', async ({ page }) => {
    let lastResponse = null;
    for (let i = 0; i <= 3; i++) {
      lastResponse = await page.goto('/user/login?_format=json');
    }
    expect(lastResponse.status()).toBe(429);
    const retryAfter = lastResponse.headers()['retry-after'];
    expect(retryAfter).toBeTruthy();
    expect(Number(retryAfter)).toBeGreaterThan(0);
  });

  test('blocked response has Cache-Control: no-store header', async ({ page }) => {
    let lastResponse = null;
    for (let i = 0; i <= 3; i++) {
      lastResponse = await page.goto('/user/login?_format=json');
    }
    expect(lastResponse.status()).toBe(429);
    const cacheControl = lastResponse.headers()['cache-control'] || '';
    expect(cacheControl).toContain('no-store');
  });

});

// ─────────────────────────────────────────────────────────────────────────────

test.describe('API Flood Guard — IP Reputation Settings', () => {

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('IP Reputation section is present on the settings page', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('body')).toContainText('IP Reputation');
  });

  test('enabled_provider select field is present', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('[name="enabled_provider"]')).toBeVisible();
  });

  test('enabled_provider has "None (disabled)" option', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    const options = await page.locator('[name="enabled_provider"] option').allTextContents();
    expect(options.some((o) => o.toLowerCase().includes('none'))).toBe(true);
  });

  test('enabled_provider has "AbuseIPDB" option', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    const options = await page.locator('[name="enabled_provider"] option').allTextContents();
    expect(options.some((o) => o.includes('AbuseIPDB'))).toBe(true);
  });

  test('AbuseIPDB threshold field is present', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('[name="threshold"]')).toBeVisible();
  });

  test('saving AbuseIPDB threshold value persists correctly', async ({ page }) => {
    await fillAndSubmitSettingsForm(page, {
      threshold: '75',
    });
    await expect(
      page.locator('.messages--status, .messages.status, [data-drupal-messages]')
    ).toContainText('The configuration options have been saved.', { timeout: 10_000 });

    // Verify the field shows the saved value after reload.
    await page.goto(SETTINGS_PATH);
    const savedValue = await page.locator('[name="threshold"]').inputValue();
    expect(savedValue).toBe('75');

    // Restore default.
    await fillAndSubmitSettingsForm(page, { threshold: '85' });
  });

});
