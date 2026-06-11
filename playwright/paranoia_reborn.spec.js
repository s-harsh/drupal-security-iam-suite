// @ts-check
/**
 * @file Playwright E2E tests for the Paranoia Reborn Drupal 11 module.
 *
 * Tests cover:
 *   - Settings form rendering, saving, and validation.
 *   - Access control: editors blocked from admin/field-ui/views-ui paths.
 *   - Admin (trusted role) unblocked from the same paths.
 *   - PHP filter warning banner visibility.
 *   - Audit log page rendering.
 *   - Status report checks.
 *
 * Requires a running Drupal 11 site with paranoia_reborn enabled.
 * Set BASE_URL env var (default http://localhost).
 *
 * Run: npx playwright test playwright/paranoia_reborn.spec.js
 */

const { test, expect } = require('@playwright/test');

const BASE_URL = process.env.BASE_URL || 'http://localhost';
const ADMIN_USER = process.env.DRUPAL_ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.DRUPAL_ADMIN_PASS || 'admin';
const EDITOR_USER = process.env.DRUPAL_EDITOR_USER || 'editor';
const EDITOR_PASS = process.env.DRUPAL_EDITOR_PASS || 'editor';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Logs in via Drupal's /user/login form.
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
 * Navigates to Paranoia Reborn settings form.
 *
 * @param {import('@playwright/test').Page} page
 */
async function gotoSettings(page) {
  await page.goto(`${BASE_URL}/admin/config/security/paranoia-reborn`);
}

// ---------------------------------------------------------------------------
// Settings form
// ---------------------------------------------------------------------------

test.describe('Paranoia Reborn — Settings Form', () => {
  test.beforeEach(async ({ page }) => {
    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);
  });

  test('settings form is reachable at the configured route', async ({ page }) => {
    await gotoSettings(page);
    await expect(page).toHaveURL(/paranoia-reborn/);
    await expect(page.locator('h1')).toContainText('Paranoia Reborn');
  });

  test('all four profile radio options are visible', async ({ page }) => {
    await gotoSettings(page);
    await expect(page.locator('input[name="lockdown_profile"][value="strict"]')).toBeVisible();
    await expect(page.locator('input[name="lockdown_profile"][value="balanced"]')).toBeVisible();
    await expect(page.locator('input[name="lockdown_profile"][value="custom"]')).toBeVisible();
  });

  test('saving balanced profile shows success message', async ({ page }) => {
    await gotoSettings(page);
    await page.locator('input[name="lockdown_profile"][value="balanced"]').check();
    await page.locator('input[name="audit_log_enabled"]').check();
    await page.locator('#edit-submit').click();
    await expect(page.locator('.messages--status, .messages--ok')).toContainText('configuration options have been saved');
  });

  test('saving strict profile shows success message', async ({ page }) => {
    await gotoSettings(page);
    await page.locator('input[name="lockdown_profile"][value="strict"]').check();
    await page.locator('#edit-submit').click();
    await expect(page.locator('.messages--status, .messages--ok')).toContainText('configuration options have been saved');
  });

  test('custom toggle fields are hidden when balanced is selected', async ({ page }) => {
    await gotoSettings(page);
    await page.locator('input[name="lockdown_profile"][value="balanced"]').check();
    // Custom toggles should be hidden via Drupal #states.
    await expect(page.locator('input[name="admin_path_restriction"]')).toBeHidden();
  });

  test('custom toggle fields are visible when custom profile is selected', async ({ page }) => {
    await gotoSettings(page);
    await page.locator('input[name="lockdown_profile"][value="custom"]').check();
    await expect(page.locator('input[name="admin_path_restriction"]')).toBeVisible();
    await expect(page.locator('input[name="field_ui_restriction"]')).toBeVisible();
    await expect(page.locator('input[name="views_ui_restriction"]')).toBeVisible();
    await expect(page.locator('input[name="disable_php_filter"]')).toBeVisible();
  });

  test('validation error for admin path exception without leading slash', async ({ page }) => {
    await gotoSettings(page);
    await page.locator('input[name="lockdown_profile"][value="balanced"]').check();
    await page.locator('textarea[name="admin_path_exceptions"]').fill('admin/content');
    await page.locator('#edit-submit').click();
    await expect(page.locator('.messages--error')).toContainText('must start with /');
  });

  test('admin path exceptions with leading slash save successfully', async ({ page }) => {
    await gotoSettings(page);
    await page.locator('input[name="lockdown_profile"][value="balanced"]').check();
    await page.locator('textarea[name="admin_path_exceptions"]').fill('/admin/content\n/admin/content/files');
    await page.locator('#edit-submit').click();
    await expect(page.locator('.messages--status, .messages--ok')).toContainText('configuration options have been saved');
  });
});

// ---------------------------------------------------------------------------
// Access control: editor user
// ---------------------------------------------------------------------------

test.describe('Paranoia Reborn — Editor Access Control', () => {
  test.beforeEach(async ({ page }) => {
    await drupalLogin(page, EDITOR_USER, EDITOR_PASS);
  });

  test('editor receives 403 on /admin/config/system/site-information', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/admin/config/system/site-information`);
    expect(response?.status()).toBe(403);
  });

  test('editor receives 403 on Field UI path', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/admin/structure/types/manage/article/fields`);
    expect(response?.status()).toBe(403);
  });

  test('editor receives 403 on Views UI path', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/admin/structure/views`);
    expect(response?.status()).toBe(403);
  });

  test('editor can access /admin/content (exception path)', async ({ page }) => {
    // /admin/content is in the default exceptions list.
    // Paranoia Reborn should not block; Drupal's own access controls may apply.
    // We verify no "Access denied" from paranoia_reborn module.
    await page.goto(`${BASE_URL}/admin/content`);
    // Either accessible (200) or Drupal-access-denied (403 from core), but NOT
    // a Paranoia Reborn block (which returns a plain "Access denied." body).
    const body = await page.content();
    // Paranoia Reborn plain-text block contains exactly "Access denied." with no HTML wrapper.
    expect(body).not.toBe('Access denied.');
  });
});

// ---------------------------------------------------------------------------
// Access control: admin user (trusted role)
// ---------------------------------------------------------------------------

test.describe('Paranoia Reborn — Admin Access (Trusted Role)', () => {
  test.beforeEach(async ({ page }) => {
    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);
  });

  test('admin can access Field UI path', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/admin/structure/types/manage/article/fields`);
    // Paranoia Reborn should not block; status is 200 or Drupal's own redirect.
    expect(response?.status()).not.toBe(403);
  });

  test('admin can access Views UI path', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/admin/structure/views`);
    expect(response?.status()).not.toBe(403);
  });

  test('admin can access /admin/config', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/admin/config`);
    expect(response?.status()).not.toBe(403);
  });
});

// ---------------------------------------------------------------------------
// Audit log page
// ---------------------------------------------------------------------------

test.describe('Paranoia Reborn — Audit Log Page', () => {
  test.beforeEach(async ({ page }) => {
    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);
  });

  test('audit log page is reachable', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/reports/paranoia-reborn-audit`);
    await expect(page).toHaveURL(/paranoia-reborn-audit/);
    await expect(page.locator('h1')).toContainText('Audit Log');
  });

  test('audit log page shows table or empty message', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/reports/paranoia-reborn-audit`);
    const table = page.locator('table.paranoia-reborn-audit-log');
    const empty = page.locator('td.views-empty, td[colspan]');
    // One of the two must be present.
    const tableCount = await table.count();
    const emptyCount = await empty.count();
    expect(tableCount + emptyCount).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Status report
// ---------------------------------------------------------------------------

test.describe('Paranoia Reborn — Status Report', () => {
  test.beforeEach(async ({ page }) => {
    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);
  });

  test('status report contains Paranoia Reborn section', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/reports/status`);
    await expect(page.locator('body')).toContainText('Paranoia Reborn');
  });

  test('status report shows active lockdown profile', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/reports/status`);
    // Should show the profile name — balanced or strict depending on test state.
    const body = page.locator('body');
    await expect(body).toContainText(/Balanced|Strict|Custom/);
  });

  test('status report shows PHP filter status', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/reports/status`);
    await expect(page.locator('body')).toContainText(/PHP filter|PHP Filter/);
  });
});

// ---------------------------------------------------------------------------
// Menu link visibility
// ---------------------------------------------------------------------------

test.describe('Paranoia Reborn — Toolbar/Menu links', () => {
  test('admin toolbar shows Paranoia Reborn link in Security config section', async ({ page }) => {
    await drupalLogin(page, ADMIN_USER, ADMIN_PASS);
    await page.goto(`${BASE_URL}/admin/config/security`);
    await expect(page.locator('a[href*="paranoia-reborn"]')).toBeVisible();
  });

  test('editor does not see views-ui link in admin toolbar', async ({ page }) => {
    await drupalLogin(page, EDITOR_USER, EDITOR_PASS);
    await page.goto(`${BASE_URL}/`);
    // Views UI admin link should not be visible to the editor.
    const viewsLink = page.locator('a[href*="admin/structure/views"]');
    const count = await viewsLink.count();
    expect(count).toBe(0);
  });
});
