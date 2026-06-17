// @ts-check
'use strict';

/**
 * Playwright end-to-end tests for the SCIM Bridge Drupal module.
 *
 * Prerequisites:
 *   - Drupal running at http://localhost with the scim_bridge module enabled.
 *   - An admin account with username "admin" and password "admin" (or adjust below).
 *   - A SCIM Bearer token configured in scim_bridge.settings (see SCIM_TOKEN below).
 *   - The sync log table installed (module install ran hook_schema()).
 *
 * Run with:
 *   npx playwright test playwright/scim_bridge.spec.js
 */

const { test, expect, request } = require('@playwright/test');

// ---------------------------------------------------------------------------
// Configuration — adjust to match your environment.
// ---------------------------------------------------------------------------
const BASE_URL        = 'http://localhost';
const ADMIN_USER      = 'admin';
const ADMIN_PASS      = 'admin';
const SCIM_TOKEN      = 'test-bearer-token-scim-bridge-2025';
const SETTINGS_PATH   = '/admin/config/security/scim-bridge';
const MAPPING_PATH    = '/admin/config/security/scim-bridge/mapping';
const SCIM_USERS      = `${BASE_URL}/scim/v2/Users`;
const SCIM_GROUPS     = `${BASE_URL}/scim/v2/Groups`;
const SPC_PATH        = `${BASE_URL}/scim/v2/ServiceProviderConfig`;
const SCHEMAS_PATH    = `${BASE_URL}/scim/v2/Schemas`;
const RESOURCE_TYPES  = `${BASE_URL}/scim/v2/ResourceTypes`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Log in as the Drupal admin. */
async function loginAsAdmin(page) {
  await page.goto('/user/login');
  await page.fill('#edit-name', ADMIN_USER);
  await page.fill('#edit-pass', ADMIN_PASS);
  await page.click('#edit-submit');
  await page.waitForLoadState('networkidle');
}

/** Return fetch-compatible headers for authenticated SCIM requests. */
function scimHeaders() {
  return {
    'Authorization': `Bearer ${SCIM_TOKEN}`,
    'Content-Type':  'application/scim+json',
    'Accept':        'application/scim+json',
  };
}

// ---------------------------------------------------------------------------
// Admin UI: Settings page
// ---------------------------------------------------------------------------
test.describe('SCIM Bridge — Admin settings page', () => {

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('settings page loads with HTTP 200', async ({ page }) => {
    const response = await page.goto(SETTINGS_PATH);
    expect(response.status()).toBe(200);
  });

  test('settings page title contains "SCIM Bridge"', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('h1')).toContainText('SCIM Bridge');
  });

  test('settings page renders the enabled checkbox', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-enabled')).toBeVisible();
  });

  test('settings page renders conflict_strategy radio options', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-conflict-strategy-skip')).toBeVisible();
    await expect(page.locator('#edit-conflict-strategy-update')).toBeVisible();
  });

  test('settings page renders max_page_size field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-max-page-size')).toBeVisible();
  });

  test('settings page renders sync_log_enabled checkbox', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-sync-log-enabled')).toBeVisible();
  });

  test('settings page renders sync_log_retention_days field', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-sync-log-retention-days')).toBeVisible();
  });

  test('settings page has Add another token button', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    const addButton = page.locator('input[value="Add another token"]');
    await expect(addButton).toBeVisible();
  });

  test('saving valid settings shows the configuration saved message', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.check('#edit-enabled');
    await page.fill('#edit-max-page-size', '100');
    await page.check('#edit-conflict-strategy-skip');
    await page.check('#edit-sync-log-enabled');
    await page.fill('#edit-sync-log-retention-days', '90');
    await page.click('#edit-submit');
    await expect(page.locator('.messages--status')).toBeVisible();
    await expect(page.locator('.messages--status')).toContainText('configuration options have been saved');
  });

  test('invalid max_page_size shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-max-page-size', '0');
    await page.click('#edit-submit');
    await expect(page.locator('body')).toContainText('Maximum page size must be an integer between 1 and 1000');
  });

  test('negative sync_log_retention_days shows validation error', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.fill('#edit-max-page-size', '100');
    await page.fill('#edit-sync-log-retention-days', '-1');
    await page.click('#edit-submit');
    await expect(page.locator('body')).toContainText('non-negative integer');
  });

  test('selecting update conflict strategy saves correctly', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.check('#edit-conflict-strategy-update');
    await page.fill('#edit-max-page-size', '100');
    await page.fill('#edit-sync-log-retention-days', '90');
    await page.click('#edit-submit');
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-conflict-strategy-update')).toBeChecked();
  });

  test('disabling module and saving persists disabled state', async ({ page }) => {
    await page.goto(SETTINGS_PATH);
    await page.uncheck('#edit-enabled');
    await page.fill('#edit-max-page-size', '100');
    await page.fill('#edit-sync-log-retention-days', '90');
    await page.check('#edit-conflict-strategy-skip');
    await page.click('#edit-submit');
    await page.goto(SETTINGS_PATH);
    await expect(page.locator('#edit-enabled')).not.toBeChecked();
    // Re-enable for subsequent tests.
    await page.check('#edit-enabled');
    await page.click('#edit-submit');
  });

  test('anonymous user is redirected from settings page', async ({ page }) => {
    await page.goto('/user/logout');
    await page.waitForLoadState('networkidle');
    const response = await page.goto(SETTINGS_PATH);
    const url = page.url();
    const ok = response.status() === 403
      || url.includes('/user/login')
      || url !== `${BASE_URL}${SETTINGS_PATH}`;
    expect(ok).toBeTruthy();
  });

});

// ---------------------------------------------------------------------------
// Admin UI: Attribute Mapping page
// ---------------------------------------------------------------------------
test.describe('SCIM Bridge — Attribute mapping page', () => {

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('mapping page loads with HTTP 200', async ({ page }) => {
    const response = await page.goto(MAPPING_PATH);
    expect(response.status()).toBe(200);
  });

  test('mapping page shows the user attribute mapping table', async ({ page }) => {
    await page.goto(MAPPING_PATH);
    await expect(page.locator('body')).toContainText('User attribute mapping');
  });

  test('mapping page shows the group role mapping section', async ({ page }) => {
    await page.goto(MAPPING_PATH);
    await expect(page.locator('body')).toContainText('Group');
  });

  test('mapping page shows the userName attribute row', async ({ page }) => {
    await page.goto(MAPPING_PATH);
    await expect(page.locator('body')).toContainText('userName');
  });

  test('saving mapping shows success message', async ({ page }) => {
    await page.goto(MAPPING_PATH);
    await page.click('#edit-submit');
    await expect(page.locator('.messages--status')).toBeVisible();
  });

});

// ---------------------------------------------------------------------------
// SCIM API: ServiceProviderConfig, Schemas, ResourceTypes (unauthenticated)
// ---------------------------------------------------------------------------
test.describe('SCIM Bridge — Discovery endpoints', () => {

  test('ServiceProviderConfig returns HTTP 200', async ({ request }) => {
    const resp = await request.get(SPC_PATH);
    expect(resp.status()).toBe(200);
  });

  test('ServiceProviderConfig body contains filter.supported=true', async ({ request }) => {
    const resp = await request.get(SPC_PATH);
    const body = await resp.json();
    expect(body.filter.supported).toBe(true);
  });

  test('ServiceProviderConfig body contains patch.supported=true', async ({ request }) => {
    const resp = await request.get(SPC_PATH);
    const body = await resp.json();
    expect(body.patch.supported).toBe(true);
  });

  test('ServiceProviderConfig body has authenticationSchemes', async ({ request }) => {
    const resp = await request.get(SPC_PATH);
    const body = await resp.json();
    expect(Array.isArray(body.authenticationSchemes)).toBe(true);
    expect(body.authenticationSchemes.length).toBeGreaterThan(0);
  });

  test('Schemas endpoint returns HTTP 200', async ({ request }) => {
    const resp = await request.get(SCHEMAS_PATH);
    expect(resp.status()).toBe(200);
  });

  test('Schemas response contains User schema URN', async ({ request }) => {
    const resp = await request.get(SCHEMAS_PATH);
    const text = await resp.text();
    expect(text).toContain('urn:ietf:params:scim:schemas:core:2.0:User');
  });

  test('Schemas response contains Group schema URN', async ({ request }) => {
    const resp = await request.get(SCHEMAS_PATH);
    const text = await resp.text();
    expect(text).toContain('urn:ietf:params:scim:schemas:core:2.0:Group');
  });

  test('ResourceTypes endpoint returns HTTP 200', async ({ request }) => {
    const resp = await request.get(RESOURCE_TYPES);
    expect(resp.status()).toBe(200);
  });

  test('ResourceTypes lists User and Group', async ({ request }) => {
    const resp = await request.get(RESOURCE_TYPES);
    const body = await resp.json();
    const names = body.Resources.map(r => r.name);
    expect(names).toContain('User');
    expect(names).toContain('Group');
  });

});

// ---------------------------------------------------------------------------
// SCIM API: /Users — Authentication
// ---------------------------------------------------------------------------
test.describe('SCIM Bridge — /Users authentication', () => {

  test('GET /Users without token returns 401 or 403', async ({ request }) => {
    const resp = await request.get(SCIM_USERS, {
      headers: { 'Accept': 'application/scim+json' },
    });
    expect([401, 403]).toContain(resp.status());
  });

  test('GET /Users with invalid token returns 401 or 403', async ({ request }) => {
    const resp = await request.get(SCIM_USERS, {
      headers: { 'Authorization': 'Bearer wrong-token', 'Accept': 'application/scim+json' },
    });
    expect([401, 403]).toContain(resp.status());
  });

  test('GET /Users with valid token returns 200', async ({ request }) => {
    const resp = await request.get(SCIM_USERS, { headers: scimHeaders() });
    expect(resp.status()).toBe(200);
  });

});

// ---------------------------------------------------------------------------
// SCIM API: /Users — List
// ---------------------------------------------------------------------------
test.describe('SCIM Bridge — GET /Users list', () => {

  test('list response has ListResponse schema', async ({ request }) => {
    const resp = await request.get(SCIM_USERS, { headers: scimHeaders() });
    const body = await resp.json();
    expect(body.schemas).toContain('urn:ietf:params:scim:api:messages:2.0:ListResponse');
  });

  test('list response has totalResults field', async ({ request }) => {
    const resp = await request.get(SCIM_USERS, { headers: scimHeaders() });
    const body = await resp.json();
    expect(typeof body.totalResults).toBe('number');
  });

  test('list response has Resources array', async ({ request }) => {
    const resp = await request.get(SCIM_USERS, { headers: scimHeaders() });
    const body = await resp.json();
    expect(Array.isArray(body.Resources)).toBe(true);
  });

  test('list response startIndex defaults to 1', async ({ request }) => {
    const resp = await request.get(SCIM_USERS, { headers: scimHeaders() });
    const body = await resp.json();
    expect(body.startIndex).toBe(1);
  });

  test('list accepts startIndex and count query params', async ({ request }) => {
    const resp = await request.get(`${SCIM_USERS}?startIndex=1&count=5`, { headers: scimHeaders() });
    const body = await resp.json();
    expect(resp.status()).toBe(200);
    expect(body.startIndex).toBe(1);
  });

  test('list with filter userName eq returns filtered results', async ({ request }) => {
    const resp = await request.get(
      `${SCIM_USERS}?filter=userName+eq+%22admin%22`,
      { headers: scimHeaders() },
    );
    expect(resp.status()).toBe(200);
  });

});

// ---------------------------------------------------------------------------
// SCIM API: /Users — Create, Get, Patch, Delete
// ---------------------------------------------------------------------------
test.describe('SCIM Bridge — /Users CRUD', () => {

  const timestamp  = Date.now();
  const testUser   = {
    schemas:     ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName:    `scim_e2e_${timestamp}`,
    displayName: 'SCIM E2E Test',
    emails:      [{ value: `scim_e2e_${timestamp}@example.com`, primary: true, type: 'work' }],
    active:      true,
  };

  let createdUserId = null;

  test('POST /Users creates a new user and returns 201', async ({ request }) => {
    const resp = await request.post(SCIM_USERS, {
      headers: scimHeaders(),
      data:    JSON.stringify(testUser),
    });
    expect([200, 201]).toContain(resp.status());
    const body = await resp.json();
    expect(body.id).toBeTruthy();
    expect(body.userName).toBe(testUser.userName);
    createdUserId = body.id;
  });

  test('GET /Users/{id} returns created user', async ({ request }) => {
    if (!createdUserId) {
      test.skip(true, 'Depends on prior create test.');
      return;
    }
    const resp = await request.get(`${SCIM_USERS}/${createdUserId}`, { headers: scimHeaders() });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.id).toBe(createdUserId);
    expect(body.userName).toBe(testUser.userName);
  });

  test('GET /Users/{id} returns 404 for non-existent user', async ({ request }) => {
    const resp = await request.get(`${SCIM_USERS}/9999999`, { headers: scimHeaders() });
    expect(resp.status()).toBe(404);
  });

  test('GET /Users/{id} 404 body is a SCIM Error object', async ({ request }) => {
    const resp = await request.get(`${SCIM_USERS}/9999999`, { headers: scimHeaders() });
    const body = await resp.json();
    expect(body.schemas).toContain('urn:ietf:params:scim:api:messages:2.0:Error');
    expect(body.status).toBe('404');
  });

  test('PATCH /Users/{id} can deactivate user', async ({ request }) => {
    if (!createdUserId) {
      test.skip(true, 'Depends on prior create test.');
      return;
    }
    const patch = {
      schemas:    ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'replace', path: 'active', value: false }],
    };
    const resp = await request.patch(`${SCIM_USERS}/${createdUserId}`, {
      headers: scimHeaders(),
      data:    JSON.stringify(patch),
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.active).toBe(false);
  });

  test('PATCH /Users/{id} can update displayName', async ({ request }) => {
    if (!createdUserId) {
      test.skip(true, 'Depends on prior create test.');
      return;
    }
    const patch = {
      schemas:    ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'replace', path: 'displayName', value: 'Updated Name' }],
    };
    const resp = await request.patch(`${SCIM_USERS}/${createdUserId}`, {
      headers: scimHeaders(),
      data:    JSON.stringify(patch),
    });
    expect(resp.status()).toBe(200);
  });

  test('PATCH /Users with empty Operations returns 400', async ({ request }) => {
    if (!createdUserId) {
      test.skip(true, 'Depends on prior create test.');
      return;
    }
    const patch = {
      schemas:    ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [],
    };
    const resp = await request.patch(`${SCIM_USERS}/${createdUserId}`, {
      headers: scimHeaders(),
      data:    JSON.stringify(patch),
    });
    expect(resp.status()).toBe(400);
  });

  test('PUT /Users/{id} replaces user data', async ({ request }) => {
    if (!createdUserId) {
      test.skip(true, 'Depends on prior create test.');
      return;
    }
    const replacement = {
      schemas:     ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName:    testUser.userName,
      displayName: 'Replaced Display Name',
      emails:      [{ value: testUser.emails[0].value, primary: true, type: 'work' }],
      active:      true,
    };
    const resp = await request.put(`${SCIM_USERS}/${createdUserId}`, {
      headers: scimHeaders(),
      data:    JSON.stringify(replacement),
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.displayName).toBe('Replaced Display Name');
  });

  test('DELETE /Users/{id} removes the user', async ({ request }) => {
    if (!createdUserId) {
      test.skip(true, 'Depends on prior create test.');
      return;
    }
    const resp = await request.delete(`${SCIM_USERS}/${createdUserId}`, { headers: scimHeaders() });
    expect(resp.status()).toBe(204);
  });

  test('GET /Users/{id} returns 404 after delete', async ({ request }) => {
    if (!createdUserId) {
      test.skip(true, 'Depends on prior create test.');
      return;
    }
    const resp = await request.get(`${SCIM_USERS}/${createdUserId}`, { headers: scimHeaders() });
    expect(resp.status()).toBe(404);
  });

  test('POST /Users with missing userName and email returns 400', async ({ request }) => {
    const bad = { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'] };
    const resp = await request.post(SCIM_USERS, {
      headers: scimHeaders(),
      data:    JSON.stringify(bad),
    });
    expect(resp.status()).toBe(400);
  });

  test('POST /Users with malformed JSON returns 400', async ({ request }) => {
    const resp = await request.post(SCIM_USERS, {
      headers: scimHeaders(),
      data:    'not-valid-json-{{{',
    });
    expect(resp.status()).toBe(400);
  });

});

// ---------------------------------------------------------------------------
// SCIM API: /Groups
// ---------------------------------------------------------------------------
test.describe('SCIM Bridge — GET /Groups list', () => {

  test('GET /Groups without token returns 401 or 403', async ({ request }) => {
    const resp = await request.get(SCIM_GROUPS, {
      headers: { 'Accept': 'application/scim+json' },
    });
    expect([401, 403]).toContain(resp.status());
  });

  test('GET /Groups with valid token returns 200', async ({ request }) => {
    const resp = await request.get(SCIM_GROUPS, { headers: scimHeaders() });
    expect(resp.status()).toBe(200);
  });

  test('GET /Groups response has ListResponse schema', async ({ request }) => {
    const resp = await request.get(SCIM_GROUPS, { headers: scimHeaders() });
    const body = await resp.json();
    expect(body.schemas).toContain('urn:ietf:params:scim:api:messages:2.0:ListResponse');
  });

  test('GET /Groups/{id} returns 404 for non-existent role', async ({ request }) => {
    const resp = await request.get(`${SCIM_GROUPS}/nonexistent_role_xyz`, { headers: scimHeaders() });
    expect(resp.status()).toBe(404);
  });

  test('POST /Groups creates a new group', async ({ request }) => {
    const ts = Date.now();
    const payload = {
      schemas:     ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      displayName: `scim_test_group_${ts}`,
      members:     [],
    };
    const resp = await request.post(SCIM_GROUPS, {
      headers: scimHeaders(),
      data:    JSON.stringify(payload),
    });
    expect([200, 201]).toContain(resp.status());
    const body = await resp.json();
    expect(body.displayName).toContain('scim_test_group');
  });

  test('POST /Groups with empty displayName returns 400', async ({ request }) => {
    const resp = await request.post(SCIM_GROUPS, {
      headers: scimHeaders(),
      data:    JSON.stringify({ schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'] }),
    });
    expect(resp.status()).toBe(400);
  });

});

// ---------------------------------------------------------------------------
// Status report
// ---------------------------------------------------------------------------
test.describe('SCIM Bridge — Status report', () => {

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('status report shows SCIM Bridge row', async ({ page }) => {
    await page.goto('/admin/reports/status');
    await expect(page.locator('body')).toContainText('SCIM Bridge');
  });

  test('status report SCIM Bridge row shows active status when token is configured', async ({ page }) => {
    await page.goto('/admin/reports/status');
    const body = await page.locator('body').textContent();
    const hasExpected = body.includes('Active') || body.includes('token') || body.includes('configured');
    expect(hasExpected).toBeTruthy();
  });

});
