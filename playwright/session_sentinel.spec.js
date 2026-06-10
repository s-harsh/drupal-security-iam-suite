// @ts-check
/**
 * @file
 * Playwright end-to-end tests for the Session Sentinel Drupal module.
 *
 * Test coverage:
 *   1. Settings form renders and saves configuration.
 *   2. Invalid settings are rejected with visible error messages.
 *   3. Admin dashboard renders a table with the correct columns.
 *   4. Dashboard JSON endpoint returns valid data.
 *   5. JS countdown warning banner appears when idle time is near expiry.
 *   6. "Stay logged in" button dismisses the warning banner.
 *   7. Session is forcibly redirected to login on expiry.
 *
 * Prerequisites:
 *   - A running Drupal site with session_sentinel enabled.
 *   - BASE_URL env var pointing to the Drupal root (default: http://localhost:8888).
 *   - ADMIN_USER / ADMIN_PASS env vars (default: admin / admin).
 */

const { test, expect } = require('@playwright/test');

const BASE_URL   = process.env.BASE_URL   || 'http://localhost:8888';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';

const SETTINGS_URL   = `${BASE_URL}/admin/config/security/session-sentinel`;
const DASHBOARD_URL  = `${BASE_URL}/admin/config/security/session-sentinel/dashboard`;
const DATA_URL       = `${BASE_URL}/admin/config/security/session-sentinel/dashboard/data?_format=json`;
const LOGIN_URL      = `${BASE_URL}/user/login`;

/**
 * Helper: log in as admin.
 *
 * @param {import('@playwright/test').Page} page
 */
async function loginAsAdmin(page) {
  await page.goto(LOGIN_URL);
  await page.fill('#edit-name', ADMIN_USER);
  await page.fill('#edit-pass', ADMIN_PASS);
  await page.click('#edit-submit');
  await page.waitForURL(`${BASE_URL}/user/**`);
}

// ---------------------------------------------------------------------------
// Settings form
// ---------------------------------------------------------------------------

test.describe('Session Sentinel — Settings Form', () => {

  test('renders the settings form for admin users', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(SETTINGS_URL);
    await expect(page).toHaveTitle(/Session Sentinel/i);
    await expect(page.locator('h1')).toContainText('Session Sentinel Settings');
  });

  test('settings form contains all expected fields', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(SETTINGS_URL);

    await expect(page.locator('#edit-idle-timeout')).toBeVisible();
    await expect(page.locator('#edit-warning-lead-time')).toBeVisible();
    await expect(page.locator('#edit-max-concurrent-sessions')).toBeVisible();
    await expect(page.locator('#edit-exempt-admins-from-limit')).toBeVisible();
    await expect(page.locator('#edit-enable-device-binding')).toBeVisible();
    await expect(page.locator('#edit-prune-age')).toBeVisible();
  });

  test('saves valid settings and shows success message', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(SETTINGS_URL);

    await page.fill('#edit-idle-timeout', '2400');
    await page.fill('#edit-warning-lead-time', '180');
    await page.fill('#edit-max-concurrent-sessions', '4');
    await page.fill('#edit-prune-age', '86400');

    await page.click('#edit-submit');

    await expect(page.locator('.messages--status')).toContainText('The configuration options have been saved');

    // Verify the saved values are reflected in the form.
    await page.goto(SETTINGS_URL);
    await expect(page.locator('#edit-idle-timeout')).toHaveValue('2400');
    await expect(page.locator('#edit-warning-lead-time')).toHaveValue('180');
  });

  test('shows error when warning lead time >= idle timeout', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(SETTINGS_URL);

    await page.fill('#edit-idle-timeout', '600');
    await page.fill('#edit-warning-lead-time', '600');
    await page.click('#edit-submit');

    await expect(page.locator('.messages--error')).toContainText('Warning lead time must be less than the idle timeout');
  });

  test('shows error for prune age below minimum', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(SETTINGS_URL);

    await page.fill('#edit-prune-age', '1000');
    await page.click('#edit-submit');

    await expect(page.locator('.messages--error')).toContainText('Prune age must be at least 3600 seconds');
  });

  test('redirects anonymous users to login', async ({ page }) => {
    await page.goto(SETTINGS_URL);
    // Should redirect to user/login or return 403.
    const url = page.url();
    expect(url).toMatch(/user\/login|403/);
  });

});

// ---------------------------------------------------------------------------
// Admin Dashboard
// ---------------------------------------------------------------------------

test.describe('Session Sentinel — Admin Dashboard', () => {

  test('renders the dashboard for admin users', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(DASHBOARD_URL);
    await expect(page).toHaveTitle(/Active Sessions/i);
    await expect(page.locator('h1')).toContainText('Active Sessions');
  });

  test('dashboard contains expected table columns', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(DASHBOARD_URL);

    const headers = page.locator('table th');
    await expect(headers).toContainText(['User', 'IP Address', 'Last Active', 'Device Flagged', 'Actions']);
  });

  test('dashboard table renders without errors', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('table')).toBeVisible();
    // No PHP errors on the page.
    await expect(page.locator('body')).not.toContainText('Fatal error');
    await expect(page.locator('body')).not.toContainText('Warning:');
  });

  test('JSON data endpoint returns valid structure', async ({ page }) => {
    await loginAsAdmin(page);

    const response = await page.request.get(DATA_URL);
    expect(response.status()).toBe(200);

    const contentType = response.headers()['content-type'] || '';
    expect(contentType).toContain('application/json');

    const body = await response.json();
    expect(body).toHaveProperty('sessions');
    expect(body).toHaveProperty('total');
    expect(body).toHaveProperty('flagged');
    expect(body).toHaveProperty('timestamp');
    expect(Array.isArray(body.sessions)).toBe(true);
  });

  test('JSON data endpoint rejects anonymous access', async ({ page }) => {
    const response = await page.request.get(DATA_URL);
    expect(response.status()).toBe(403);
  });

  test('kills a session with a valid CSRF token', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(DASHBOARD_URL);

    // If there are Kill buttons, click the first one.
    const killButton = page.locator('a:has-text("Kill")').first();
    const killButtonCount = await killButton.count();

    if (killButtonCount > 0) {
      page.on('dialog', dialog => dialog.accept());
      await killButton.click();
      await page.waitForURL(DASHBOARD_URL);
      await expect(page.locator('.messages--status')).toContainText('Session killed successfully');
    } else {
      test.skip(true, 'No active sessions to kill in this environment.');
    }
  });

});

// ---------------------------------------------------------------------------
// JS Countdown Warning Banner
// ---------------------------------------------------------------------------

test.describe('Session Sentinel — JS Countdown Warning', () => {

  test('countdown banner appears when idle time approaches expiry', async ({ page }) => {
    await loginAsAdmin(page);

    // Navigate to a page and override drupalSettings to use a very short timeout
    // so the banner triggers within the test timeout.
    await page.goto(`${BASE_URL}/admin`);

    // Inject a short idle timeout (5 seconds) and warning lead time (4 seconds)
    // so we can observe the banner quickly.
    await page.evaluate(() => {
      if (typeof drupalSettings !== 'undefined') {
        drupalSettings.sessionSentinel = {
          idleTimeout: 5,
          warningLeadTime: 4,
          keepAliveUrl: '/user/login',
          logoutUrl: '/user/logout',
        };
      }
    });

    // Wait long enough for the warning to trigger (4+ seconds idle).
    await page.waitForTimeout(5500);

    // Check that the warning banner appeared.
    const banner = page.locator('#session-sentinel-warning');
    await expect(banner).toBeVisible({ timeout: 3000 });
    await expect(banner).toContainText('session will expire');
  });

  test('"Stay logged in" button dismisses the warning banner', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(`${BASE_URL}/admin`);

    // Inject short timeout.
    await page.evaluate(() => {
      if (typeof drupalSettings !== 'undefined') {
        drupalSettings.sessionSentinel = {
          idleTimeout: 5,
          warningLeadTime: 4,
          keepAliveUrl: '/user/login',
          logoutUrl: '/user/logout',
        };
      }
    });

    // Wait for banner to appear.
    await page.waitForTimeout(5500);
    const banner = page.locator('#session-sentinel-warning');
    await expect(banner).toBeVisible({ timeout: 3000 });

    // Click "Stay logged in".
    await page.click('#session-sentinel-warning button');

    // Banner should be dismissed.
    await expect(banner).not.toBeVisible({ timeout: 2000 });
  });

  test('page redirects to login when session expires', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto(`${BASE_URL}/admin`);

    // Inject a 2-second timeout with no warning lead time.
    await page.evaluate(() => {
      if (typeof drupalSettings !== 'undefined') {
        drupalSettings.sessionSentinel = {
          idleTimeout: 2,
          warningLeadTime: 1,
          keepAliveUrl: '/user/login',
          logoutUrl: '/user/logout?destination=user/login&session_expired=1',
        };
      }
    });

    // Wait for the redirect to fire.
    await page.waitForURL(/user\/logout|user\/login/, { timeout: 10000 });
  });

});
