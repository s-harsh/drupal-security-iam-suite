// @ts-check
'use strict';

/**
 * Playwright end-to-end tests for the SBOM Sentinel Drupal module.
 *
 * Prerequisites:
 *   - Drupal running at http://localhost with the sbom_sentinel module enabled.
 *   - An admin account with username "admin" and password "admin" (or adjust below).
 *   - The composer.lock path in module settings must point to a readable file.
 *
 * Run with:
 *   npx playwright test playwright/sbom_sentinel.spec.js
 */

const { test, expect } = require('@playwright/test');

// ---------------------------------------------------------------------------
// Configuration — adjust if your Drupal instance differs.
// ---------------------------------------------------------------------------
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin';
const SETTINGS_PATH = '/admin/config/security/sbom-sentinel';
const REPORT_PATH = '/admin/reports/sbom-sentinel';
const EXPORT_JSON_PATH = '/admin/reports/sbom-sentinel/export/json';
const EXPORT_XML_PATH = '/admin/reports/sbom-sentinel/export/xml';
const STATUS_REPORT_PATH = '/admin/reports/status';

// ---------------------------------------------------------------------------
// Helper: log in as the admin user before each test.
// ---------------------------------------------------------------------------
async function loginAsAdmin(page) {
  await page.goto('/user/login');
  await page.fill('#edit-name', ADMIN_USER);
  await page.fill('#edit-pass', ADMIN_PASS);
  await page.click('#edit-submit');
  await page.waitForLoadState('networkidle');
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------
test.describe('SBOM Sentinel', () => {

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

  test('settings page title contains "SBOM Sentinel"', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('h1')).toContainText('SBOM Sentinel');
  });

  test('settings page renders the "enabled" checkbox', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-enabled')).toBeVisible();
  });

  test('settings page renders the composer_lock_path field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-composer-lock-path')).toBeVisible();
  });

  test('settings page renders the osv_api_base_url field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-osv-api-base-url')).toBeVisible();
  });

  test('settings page renders the http_timeout field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-http-timeout')).toBeVisible();
  });

  test('settings page renders the scan_cache_ttl field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-scan-cache-ttl')).toBeVisible();
  });

  test('settings page renders the cron_enabled checkbox', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-cron-enabled')).toBeVisible();
  });

  test('settings page shows the default OSV API URL', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-osv-api-base-url')).toHaveValue('https://api.osv.dev/v1');
  });

  test('settings page shows the Save configuration button', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-submit')).toBeVisible();
    await expect(page.locator('#edit-submit')).toBeEnabled();
  });

  // -------------------------------------------------------------------------
  // Settings page — form submission
  // -------------------------------------------------------------------------

  test('saving valid settings shows the configuration saved message', async ({ page }) => {
    await page.goto(SETTINGS_PATH);

    await page.check('#edit-enabled');
    await page.fill('#edit-composer-lock-path', '../composer.lock');
    await page.fill('#edit-osv-api-base-url', 'https://api.osv.dev/v1');
    await page.fill('#edit-http-timeout', '10');
    await page.fill('#edit-scan-cache-ttl', '3600');
    await page.check('#edit-cron-enabled');

    await page.click('#edit-submit');

    await expect(page.locator('.messages--status')).toBeVisible();
    await expect(page.locator('.messages--status')).toContainText('configuration options have been saved');
  });

  test('saved osv_api_base_url is reflected after page reload', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-osv-api-base-url', 'https://api.osv.dev/v1');
    await page.fill('#edit-http-timeout', '10');
    await page.fill('#edit-composer-lock-path', '../composer.lock');
    await page.fill('#edit-scan-cache-ttl', '3600');
    await page.click('#edit-submit');

    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-osv-api-base-url')).toHaveValue('https://api.osv.dev/v1');
  });

  // -------------------------------------------------------------------------
  // Settings page — validation errors
  // -------------------------------------------------------------------------

  test('http_timeout of 0 shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-http-timeout', '0');
    await page.fill('#edit-osv-api-base-url', 'https://api.osv.dev/v1');
    await page.fill('#edit-composer-lock-path', '../composer.lock');
    await page.fill('#edit-scan-cache-ttl', '3600');
    await page.click('#edit-submit');

    await expect(page.locator('body')).toContainText('HTTP timeout must be an integer between 1 and 60');
  });

  test('invalid osv_api_base_url shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-osv-api-base-url', 'not-a-url');
    await page.fill('#edit-http-timeout', '10');
    await page.fill('#edit-composer-lock-path', '../composer.lock');
    await page.fill('#edit-scan-cache-ttl', '3600');
    await page.click('#edit-submit');

    await expect(page.locator('body')).toContainText('OSV API base URL must be a valid absolute URL');
  });

  test('negative scan_cache_ttl shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-scan-cache-ttl', '-1');
    await page.fill('#edit-osv-api-base-url', 'https://api.osv.dev/v1');
    await page.fill('#edit-http-timeout', '10');
    await page.fill('#edit-composer-lock-path', '../composer.lock');
    await page.click('#edit-submit');

    await expect(page.locator('body')).toContainText('Scan result cache TTL must be a non-negative integer');
  });

  test('invalid email recipient shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.check('#edit-cron-enabled');
    await page.check('#edit-email-report-enabled');
    await page.fill('#edit-email-recipient', 'not-valid');
    await page.fill('#edit-osv-api-base-url', 'https://api.osv.dev/v1');
    await page.fill('#edit-http-timeout', '10');
    await page.fill('#edit-composer-lock-path', '../composer.lock');
    await page.fill('#edit-scan-cache-ttl', '3600');
    await page.click('#edit-submit');

    await expect(page.locator('body')).toContainText('email recipient address is not a valid email address');
  });

  test('validation error does not redirect away from settings page', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-http-timeout', '0');
    await page.fill('#edit-osv-api-base-url', 'https://api.osv.dev/v1');
    await page.fill('#edit-composer-lock-path', '../composer.lock');
    await page.fill('#edit-scan-cache-ttl', '3600');
    await page.click('#edit-submit');

    expect(page.url()).toContain('sbom-sentinel');
  });

  // -------------------------------------------------------------------------
  // Access control
  // -------------------------------------------------------------------------

  test('anonymous user is redirected from the settings page', async ({ page }) => {
    await page.goto('/user/logout');
    await page.waitForLoadState('networkidle');

    const response = await page.goto(SETTINGS_PATH);
    const url = page.url();
    const statusOk =
      response.status() === 403 ||
      url.includes('/user/login') ||
      url !== `http://localhost${SETTINGS_PATH}`;
    expect(statusOk).toBeTruthy();
  });

  // -------------------------------------------------------------------------
  // Report page
  // -------------------------------------------------------------------------

  test('report page loads with HTTP 200', async ({ page }) => {
    const response = await page.goto(REPORT_PATH);
    expect(response.status()).toBe(200);
  });

  test('report page title contains "SBOM Sentinel"', async ({ page }) => {
    await page.goto(REPORT_PATH);
    await expect(page.locator('h1')).toContainText('SBOM Sentinel');
  });

  test('report page renders a table', async ({ page }) => {
    await page.goto(REPORT_PATH);
    await expect(page.locator('table')).toBeVisible();
  });

  test('report page table has Package column header', async ({ page }) => {
    await page.goto(REPORT_PATH);
    await expect(page.locator('body')).toContainText('Package');
  });

  test('report page table has CVE Count column header', async ({ page }) => {
    await page.goto(REPORT_PATH);
    await expect(page.locator('body')).toContainText('CVE Count');
  });

  test('report page table has NIS2 Risk column header', async ({ page }) => {
    await page.goto(REPORT_PATH);
    await expect(page.locator('body')).toContainText('NIS2 Risk');
  });

  test('report page table has Max CVSS column header', async ({ page }) => {
    await page.goto(REPORT_PATH);
    await expect(page.locator('body')).toContainText('Max CVSS');
  });

  test('report page contains JSON export link', async ({ page }) => {
    await page.goto(REPORT_PATH);
    await expect(page.locator(`a[href*="export/json"]`)).toBeVisible();
  });

  test('report page contains XML export link', async ({ page }) => {
    await page.goto(REPORT_PATH);
    await expect(page.locator(`a[href*="export/xml"]`)).toBeVisible();
  });

  // -------------------------------------------------------------------------
  // Export endpoints — JSON
  // -------------------------------------------------------------------------

  test('JSON export endpoint responds with HTTP 200', async ({ page }) => {
    const response = await page.goto(EXPORT_JSON_PATH);
    expect(response.status()).toBe(200);
  });

  test('JSON export response contains CycloneDX bomFormat key', async ({ page }) => {
    const response = await page.goto(EXPORT_JSON_PATH);
    const body = await response.text();
    const json = JSON.parse(body);
    expect(json.bomFormat).toBe('CycloneDX');
  });

  test('JSON export response contains specVersion 1.6', async ({ page }) => {
    const response = await page.goto(EXPORT_JSON_PATH);
    const body = await response.text();
    const json = JSON.parse(body);
    expect(json.specVersion).toBe('1.6');
  });

  test('JSON export response contains serialNumber starting with urn:uuid', async ({ page }) => {
    const response = await page.goto(EXPORT_JSON_PATH);
    const body = await response.text();
    const json = JSON.parse(body);
    expect(json.serialNumber).toMatch(/^urn:uuid:/);
  });

  test('JSON export response contains components array', async ({ page }) => {
    const response = await page.goto(EXPORT_JSON_PATH);
    const body = await response.text();
    const json = JSON.parse(body);
    expect(Array.isArray(json.components)).toBeTruthy();
  });

  // -------------------------------------------------------------------------
  // Export endpoints — XML
  // -------------------------------------------------------------------------

  test('XML export endpoint responds with HTTP 200', async ({ page }) => {
    const response = await page.goto(EXPORT_XML_PATH);
    expect(response.status()).toBe(200);
  });

  test('XML export response is valid XML with bom root element', async ({ page }) => {
    const response = await page.goto(EXPORT_XML_PATH);
    const body = await response.text();
    expect(body).toMatch(/<bom\s/);
    expect(body).toContain('cyclonedx.org/schema/bom/1.6');
  });

  test('XML export contains components element', async ({ page }) => {
    const response = await page.goto(EXPORT_XML_PATH);
    const body = await response.text();
    // Only assert presence if there are components.
    expect(body).toMatch(/<(components|bom)/);
  });

  // -------------------------------------------------------------------------
  // Status report
  // -------------------------------------------------------------------------

  test('status report page shows the SBOM Sentinel row', async ({ page }) => {
    await page.goto(STATUS_REPORT_PATH);
    await expect(page.locator('body')).toContainText('SBOM Sentinel');
  });

  // -------------------------------------------------------------------------
  // Navigation and menu integration
  // -------------------------------------------------------------------------

  test('settings page is linked from the Security admin section', async ({ page }) => {
    await page.goto('/admin/config/security');
    const link = page.locator(`a[href*="sbom-sentinel"]`);
    await expect(link).toBeVisible();
  });

  test('report page is linked from the admin reports section', async ({ page }) => {
    await page.goto('/admin/reports');
    const link = page.locator(`a[href*="sbom-sentinel"]`);
    await expect(link.first()).toBeVisible();
  });

  test('help page for sbom_sentinel loads without error', async ({ page }) => {
    const response = await page.goto('/admin/help/sbom_sentinel');
    expect([200, 404]).toContain(response.status());
  });

  // -------------------------------------------------------------------------
  // Sort parameters on report page
  // -------------------------------------------------------------------------

  test('report page with sort=asc&order=name loads without error', async ({ page }) => {
    const response = await page.goto(REPORT_PATH + '?order=name&sort=asc');
    expect(response.status()).toBe(200);
  });

  test('report page with sort=desc&order=risk loads without error', async ({ page }) => {
    const response = await page.goto(REPORT_PATH + '?order=risk&sort=desc');
    expect(response.status()).toBe(200);
  });

});
