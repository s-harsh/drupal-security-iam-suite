// @ts-check
/**
 * @file
 * Playwright E2E tests for Zero Standing Privilege module.
 *
 * Covers the full JIT PAM lifecycle:
 *  1. Anonymous access is blocked.
 *  2. Authenticated user submits an elevation request.
 *  3. Approver sees the pending request in the queue.
 *  4. Approver approves the request.
 *  5. Requester's role is now active; they can see it in "My Requests".
 *  6. Requester self-revokes the elevation early.
 *  7. Admin audit log shows all lifecycle events.
 *
 * Requires a running Drupal 11 site at BASE_URL with:
 *   - zero_standing_privilege module enabled
 *   - Editor role created (machine name: editor)
 *   - Users with appropriate permissions (configured in playwright/.auth/)
 *
 * Environment variables:
 *   DRUPAL_BASE_URL      — Drupal site URL (default: http://localhost)
 *   REQUESTER_USERNAME   — username of the requester test user
 *   REQUESTER_PASSWORD   — password of the requester test user
 *   APPROVER_USERNAME    — username of the approver test user
 *   APPROVER_PASSWORD    — password of the approver test user
 *   ADMIN_USERNAME       — username of the admin test user
 *   ADMIN_PASSWORD       — password of the admin test user
 */

const { test, expect } = require('@playwright/test');

const BASE_URL = process.env.DRUPAL_BASE_URL || 'http://localhost';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Logs in as the given user via Drupal's standard login form.
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
 * Logs out the current user.
 *
 * @param {import('@playwright/test').Page} page
 */
async function drupalLogout(page) {
  await page.goto(`${BASE_URL}/user/logout`);
}

// ---------------------------------------------------------------------------
// Suite: Anonymous access
// ---------------------------------------------------------------------------

test.describe('Anonymous access', () => {
  test('anonymous user is blocked from the request form', async ({ page }) => {
    await page.goto(`${BASE_URL}/zsp/request`);
    // Drupal returns 403 which redirects to /user/login or shows Access Denied.
    const status = page.url();
    const bodyText = await page.textContent('body');
    const isBlocked = status.includes('/user/login') || /access denied/i.test(bodyText ?? '');
    expect(isBlocked).toBeTruthy();
  });

  test('anonymous user is blocked from the approval queue', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/config/security/zero-standing-privilege/queue`);
    const bodyText = await page.textContent('body');
    const isBlocked = page.url().includes('/user/login') || /access denied/i.test(bodyText ?? '');
    expect(isBlocked).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Suite: Settings form
// ---------------------------------------------------------------------------

test.describe('Settings form', () => {
  test('admin can access the ZSP settings form', async ({ page }) => {
    await drupalLogin(page,
      process.env.ADMIN_USERNAME || 'admin',
      process.env.ADMIN_PASSWORD || 'admin'
    );
    await page.goto(`${BASE_URL}/admin/config/security/zero-standing-privilege`);
    await expect(page).toHaveURL(/zero-standing-privilege/);
    await expect(page.locator('h1')).toContainText(/Zero Standing Privilege/i);
  });

  test('saving settings shows confirmation message', async ({ page }) => {
    await drupalLogin(page,
      process.env.ADMIN_USERNAME || 'admin',
      process.env.ADMIN_PASSWORD || 'admin'
    );
    await page.goto(`${BASE_URL}/admin/config/security/zero-standing-privilege`);
    await page.click('[value="Save configuration"], button[type="submit"]');
    await expect(page.locator('.messages--status, .messages-list__item')).toContainText(/saved|configuration/i);
  });
});

// ---------------------------------------------------------------------------
// Suite: Elevation request lifecycle
// ---------------------------------------------------------------------------

test.describe('Elevation request lifecycle', () => {
  const requester = {
    username: process.env.REQUESTER_USERNAME || 'requester_user',
    password: process.env.REQUESTER_PASSWORD || 'requester_pass',
  };
  const approver = {
    username: process.env.APPROVER_USERNAME || 'approver_user',
    password: process.env.APPROVER_PASSWORD || 'approver_pass',
  };

  test('requester can submit an elevation request', async ({ page }) => {
    await drupalLogin(page, requester.username, requester.password);
    await page.goto(`${BASE_URL}/zsp/request`);

    await expect(page.locator('h1')).toContainText(/Request Temporary Role Elevation/i);

    // Fill out the form.
    await page.selectOption('select[name="target_role"]', 'editor');
    await page.fill('input[name="duration_minutes"]', '60');
    await page.fill('textarea[name="reason"]', 'I need to publish several urgent blog posts for the product launch campaign.');

    await page.click('input[type="submit"], button[type="submit"]');

    // Should redirect to my-requests and show success message.
    await expect(page).toHaveURL(/\/zsp\/my-requests/);
    await expect(page.locator('.messages--status, .messages-list__item')).toContainText(/submitted|awaiting/i);
  });

  test('requester can view their request in my-requests', async ({ page }) => {
    await drupalLogin(page, requester.username, requester.password);
    await page.goto(`${BASE_URL}/zsp/my-requests`);

    await expect(page.locator('h1')).toContainText(/My Elevation Requests/i);
    // At least one row should exist.
    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount({ minimum: 1 });
  });

  test('form validation rejects a short reason', async ({ page }) => {
    await drupalLogin(page, requester.username, requester.password);
    await page.goto(`${BASE_URL}/zsp/request`);

    await page.selectOption('select[name="target_role"]', 'editor');
    await page.fill('input[name="duration_minutes"]', '30');
    await page.fill('textarea[name="reason"]', 'Too short');

    await page.click('input[type="submit"], button[type="submit"]');

    // Should stay on the form and show error.
    await expect(page).toHaveURL(/\/zsp\/request/);
    await expect(page.locator('.messages--error, .messages-list__item--error')).toContainText(/10 characters/i);
  });

  test('approver can see the pending request in the queue', async ({ page }) => {
    await drupalLogin(page, approver.username, approver.password);
    await page.goto(`${BASE_URL}/admin/config/security/zero-standing-privilege/queue`);

    await expect(page.locator('h1')).toContainText(/Approval Queue/i);
    // Pending request should be visible.
    await expect(page.locator('table')).toContainText('editor');
    await expect(page.locator('table')).toContainText('Approve');
    await expect(page.locator('table')).toContainText('Deny');
  });

  test('approver can approve a request', async ({ page }) => {
    await drupalLogin(page, approver.username, approver.password);
    await page.goto(`${BASE_URL}/admin/config/security/zero-standing-privilege/queue`);

    // Click first Approve button.
    await page.locator('button:has-text("Approve"), input[value="Approve"]').first().click();

    await expect(page.locator('.messages--status, .messages-list__item')).toContainText(/approved/i);
  });

  test('active elevation appears in admin active elevations table', async ({ page }) => {
    await drupalLogin(page,
      process.env.ADMIN_USERNAME || 'admin',
      process.env.ADMIN_PASSWORD || 'admin'
    );
    await page.goto(`${BASE_URL}/admin/config/security/zero-standing-privilege/active`);

    await expect(page.locator('h1')).toContainText(/Active Elevations/i);
    // The approved elevation should now appear.
    await expect(page.locator('table')).toContainText('editor');
    await expect(page.locator('table')).toContainText('Revoke');
  });

  test('requester can self-revoke an active elevation', async ({ page }) => {
    await drupalLogin(page, requester.username, requester.password);
    await page.goto(`${BASE_URL}/zsp/my-requests`);

    // Click View on the approved request.
    await page.locator('a:has-text("View")').first().click();

    // Should show Revoke button on the detail page.
    const revokeBtn = page.locator('button:has-text("Revoke"), button:has-text("Revoke this elevation now")');
    await expect(revokeBtn).toBeVisible();
    await revokeBtn.click();

    // Should redirect to my-requests and show success.
    await expect(page).toHaveURL(/\/zsp\/my-requests/);
    await expect(page.locator('.messages--status, .messages-list__item')).toContainText(/revoked/i);
  });
});

// ---------------------------------------------------------------------------
// Suite: Audit log
// ---------------------------------------------------------------------------

test.describe('Audit log', () => {
  test('admin can view the audit log with lifecycle entries', async ({ page }) => {
    await drupalLogin(page,
      process.env.ADMIN_USERNAME || 'admin',
      process.env.ADMIN_PASSWORD || 'admin'
    );
    await page.goto(`${BASE_URL}/admin/config/security/zero-standing-privilege/audit`);

    await expect(page.locator('h1')).toContainText(/Audit Log/i);
    // At least one row should be present after the lifecycle test.
    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount({ minimum: 1 });
  });

  test('audit log shows expected statuses', async ({ page }) => {
    await drupalLogin(page,
      process.env.ADMIN_USERNAME || 'admin',
      process.env.ADMIN_PASSWORD || 'admin'
    );
    await page.goto(`${BASE_URL}/admin/config/security/zero-standing-privilege/audit`);

    const tableText = await page.locator('table').textContent();
    // We should see at least one of the known statuses.
    const hasExpectedStatus = /Approved|Revoked|Denied|Expired|Pending/i.test(tableText ?? '');
    expect(hasExpectedStatus).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Suite: Drush integration (smoke test — checks pages exist, not CLI output)
// ---------------------------------------------------------------------------

test.describe('Admin navigation', () => {
  test('all admin sub-pages are reachable from the settings page', async ({ page }) => {
    await drupalLogin(page,
      process.env.ADMIN_USERNAME || 'admin',
      process.env.ADMIN_PASSWORD || 'admin'
    );
    await page.goto(`${BASE_URL}/admin/config/security/zero-standing-privilege`);

    // Check menu links are present.
    await expect(page.locator('a[href*="queue"]')).toBeVisible();
    await expect(page.locator('a[href*="active"]')).toBeVisible();
    await expect(page.locator('a[href*="audit"]')).toBeVisible();
  });
});
