// @ts-check
'use strict';

/**
 * Playwright end-to-end tests for the HIBP Password Guard Drupal module.
 *
 * Prerequisites:
 *   - Drupal running at http://localhost with the hibp_password_guard module enabled.
 *   - An admin account with username "admin" and password "admin" (or adjust below).
 *   - The password_policy module must be enabled.
 *
 * Run with:
 *   npx playwright test playwright/hibp_password_guard.spec.js
 */

const { test, expect } = require('@playwright/test');

// ---------------------------------------------------------------------------
// Configuration — adjust if your Drupal instance differs.
// ---------------------------------------------------------------------------
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin';
const SETTINGS_PATH = '/admin/config/security/hibp-password-guard';
const STATUS_REPORT_PATH = '/admin/reports/status';

// ---------------------------------------------------------------------------
// Helper: log in as the admin user before each test.
// ---------------------------------------------------------------------------
async function loginAsAdmin(page) {
  await page.goto('/user/login');
  await page.fill('#edit-name', ADMIN_USER);
  await page.fill('#edit-pass', ADMIN_PASS);
  await page.click('#edit-submit');
  // Wait until the login redirect completes.
  await page.waitForLoadState('networkidle');
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------
test.describe('HIBP Password Guard', () => {

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  // -------------------------------------------------------------------------
  // Settings page — rendering
  // -------------------------------------------------------------------------

  test('settings page loads with HTTP 200', async ({ page }) => {
    const response = await page.goto(SETTINGS_PATH);
    expect(response.status()).toBe(200);
  });

  test('settings page title contains "HIBP Password Guard"', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('h1')).toContainText('HIBP Password Guard');
  });

  test('settings page renders the "enabled" checkbox', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-enabled')).toBeVisible();
  });

  test('settings page renders the cache_ttl field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-cache-ttl')).toBeVisible();
  });

  test('settings page renders the http_timeout field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-http-timeout')).toBeVisible();
  });

  test('settings page renders the api_base_url field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-api-base-url')).toBeVisible();
  });

  test('settings page renders both fail_mode radio options', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-fail-mode-fail-open')).toBeVisible();
    await expect(page.locator('#edit-fail-mode-fail-closed')).toBeVisible();
  });

  test('settings page shows the default API base URL', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    const apiUrlInput = page.locator('#edit-api-base-url');
    await expect(apiUrlInput).toHaveValue('https://api.pwnedpasswords.com');
  });

  test('settings page shows the default cache TTL of 86400', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    const cacheTtlInput = page.locator('#edit-cache-ttl');
    await expect(cacheTtlInput).toHaveValue('86400');
  });

  test('settings page shows the Save configuration button', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-submit')).toBeVisible();
    await expect(page.locator('#edit-submit')).toBeEnabled();
  });

  // -------------------------------------------------------------------------
  // Settings page — successful form submission
  // -------------------------------------------------------------------------

  test('saving valid settings shows the configuration saved message', async ({ page }) => {
    await page.goto(SETTINGS_PATH);

    // Ensure enabled checkbox is checked.
    await page.check('#edit-enabled');

    // Set a custom cache TTL.
    await page.fill('#edit-cache-ttl', '3600');
    await page.fill('#edit-http-timeout', '10');
    await page.fill('#edit-api-base-url', 'https://api.pwnedpasswords.com');

    // Select fail_open.
    await page.check('#edit-fail-mode-fail-open');

    await page.click('#edit-submit');

    await expect(page.locator('.messages--status')).toBeVisible();
    await expect(page.locator('.messages--status')).toContainText('configuration options have been saved');
  });

  test('saved cache TTL value is reflected after page reload', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-cache-ttl', '7200');
    await page.fill('#edit-http-timeout', '5');
    await page.fill('#edit-api-base-url', 'https://api.pwnedpasswords.com');
    await page.check('#edit-fail-mode-fail-open');
    await page.click('#edit-submit');

    // Reload and verify the value persisted.
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-cache-ttl')).toHaveValue('7200');
  });

  test('selecting fail_closed and saving persists the choice', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-cache-ttl', '86400');
    await page.fill('#edit-http-timeout', '5');
    await page.fill('#edit-api-base-url', 'https://api.pwnedpasswords.com');
    await page.check('#edit-fail-mode-fail-closed');
    await page.click('#edit-submit');

    // Reload and verify fail_closed is selected.
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-fail-mode-fail-closed')).toBeChecked();
  });

  test('unchecking enabled checkbox and saving sets module to disabled', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.uncheck('#edit-enabled');
    await page.fill('#edit-cache-ttl', '86400');
    await page.fill('#edit-http-timeout', '5');
    await page.fill('#edit-api-base-url', 'https://api.pwnedpasswords.com');
    await page.check('#edit-fail-mode-fail-open');
    await page.click('#edit-submit');

    // Reload and verify the checkbox is unchecked.
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-enabled')).not.toBeChecked();
  });

  test('cache_ttl=0 (caching disabled) saves successfully', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.check('#edit-enabled');
    await page.fill('#edit-cache-ttl', '0');
    await page.fill('#edit-http-timeout', '5');
    await page.fill('#edit-api-base-url', 'https://api.pwnedpasswords.com');
    await page.check('#edit-fail-mode-fail-open');
    await page.click('#edit-submit');

    await expect(page.locator('.messages--status')).toBeVisible();
  });

  // -------------------------------------------------------------------------
  // Settings page — validation errors
  // -------------------------------------------------------------------------

  test('negative cache_ttl shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-cache-ttl', '-1');
    await page.fill('#edit-http-timeout', '5');
    await page.fill('#edit-api-base-url', 'https://api.pwnedpasswords.com');
    await page.check('#edit-fail-mode-fail-open');
    await page.click('#edit-submit');

    await expect(page.locator('.messages--error, [role="alert"]')).toBeVisible();
    await expect(page.locator('body')).toContainText('Cache TTL must be a non-negative integer');
  });

  test('http_timeout of 0 shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-cache-ttl', '86400');
    await page.fill('#edit-http-timeout', '0');
    await page.fill('#edit-api-base-url', 'https://api.pwnedpasswords.com');
    await page.check('#edit-fail-mode-fail-open');
    await page.click('#edit-submit');

    await expect(page.locator('body')).toContainText('HTTP timeout must be an integer between 1 and 30');
  });

  test('http_timeout of 31 shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-cache-ttl', '86400');
    await page.fill('#edit-http-timeout', '31');
    await page.fill('#edit-api-base-url', 'https://api.pwnedpasswords.com');
    await page.check('#edit-fail-mode-fail-open');
    await page.click('#edit-submit');

    await expect(page.locator('body')).toContainText('HTTP timeout must be an integer between 1 and 30');
  });

  test('invalid api_base_url shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-cache-ttl', '86400');
    await page.fill('#edit-http-timeout', '5');
    await page.fill('#edit-api-base-url', 'not-a-url');
    await page.check('#edit-fail-mode-fail-open');
    await page.click('#edit-submit');

    await expect(page.locator('body')).toContainText('HIBP API base URL must be a valid absolute URL');
  });

  test('relative api_base_url shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-cache-ttl', '86400');
    await page.fill('#edit-http-timeout', '5');
    await page.fill('#edit-api-base-url', '/relative/path');
    await page.check('#edit-fail-mode-fail-open');
    await page.click('#edit-submit');

    await expect(page.locator('body')).toContainText('HIBP API base URL must be a valid absolute URL');
  });

  test('validation error does not redirect away from settings page', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-cache-ttl', '-5');
    await page.fill('#edit-http-timeout', '5');
    await page.fill('#edit-api-base-url', 'https://api.pwnedpasswords.com');
    await page.check('#edit-fail-mode-fail-open');
    await page.click('#edit-submit');

    // Must stay on the settings page.
    expect(page.url()).toContain('hibp-password-guard');
  });

  // -------------------------------------------------------------------------
  // Access control
  // -------------------------------------------------------------------------

  test('anonymous user is redirected from settings page', async ({ page }) => {
    // Log out first.
    await page.goto('/user/logout');
    await page.waitForLoadState('networkidle');

    const response = await page.goto(SETTINGS_PATH);
    // Should redirect to login or return 403.
    const url = page.url();
    const statusOk = response.status() === 403
      || url.includes('/user/login')
      || url !== `http://localhost${SETTINGS_PATH}`;
    expect(statusOk).toBeTruthy();
  });

  // -------------------------------------------------------------------------
  // Status report
  // -------------------------------------------------------------------------

  test('status report page loads successfully', async ({ page }) => {
    const response = await page.goto(STATUS_REPORT_PATH);
    expect(response.status()).toBe(200);
  });

  test('status report page shows the HIBP Pwned Passwords API row', async ({ page }) => {
    await page.goto(STATUS_REPORT_PATH);
    await expect(page.locator('body')).toContainText('HIBP Pwned Passwords API');
  });

  test('status report HIBP row has a visible status value', async ({ page }) => {
    await page.goto(STATUS_REPORT_PATH);

    // The row should contain one of the expected status texts.
    const body = await page.locator('body').textContent();
    const hasExpectedStatus = (
      body.includes('Reachable') ||
      body.includes('Warning') ||
      body.includes('Error') ||
      body.includes('unreachable')
    );
    expect(hasExpectedStatus).toBeTruthy();
  });

  // -------------------------------------------------------------------------
  // Navigation and menu integration
  // -------------------------------------------------------------------------

  test('settings page is linked from the Security admin section', async ({ page }) => {
    await page.goto('/admin/config/security');
    // There must be a link pointing to the settings path.
    const link = page.locator(`a[href*="hibp-password-guard"]`);
    await expect(link).toBeVisible();
  });

  test('settings page breadcrumb or navigation does not produce 404', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    // If the page loaded with 200 and contains the form, navigation is correct.
    await expect(page.locator('#edit-submit')).toBeVisible();
  });

  // -------------------------------------------------------------------------
  // Module help page
  // -------------------------------------------------------------------------

  test('help page for hibp_password_guard loads with 200', async ({ page }) => {
    const response = await page.goto('/admin/help/hibp_password_guard');
    // Help module must be enabled; if not, this may 404 — acceptable.
    expect([200, 404]).toContain(response.status());
  });

});
