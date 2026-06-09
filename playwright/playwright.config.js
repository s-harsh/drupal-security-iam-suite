// @ts-check
'use strict';

/**
 * Playwright configuration for HIBP Password Guard browser tests.
 *
 * All tests assume a local Drupal installation running at http://localhost.
 * Adjust baseURL if your site runs on a different port or path prefix.
 *
 * Run all tests:
 *   npx playwright test
 *
 * Run only the HIBP spec:
 *   npx playwright test playwright/hibp_password_guard.spec.js
 *
 * Run in headed mode (visible browser):
 *   npx playwright test --headed
 *
 * Run with a specific browser:
 *   npx playwright test --project=firefox
 */

/** @type {import('@playwright/test').PlaywrightTestConfig} */
module.exports = {
  testDir: '.',

  /* Maximum time one test can run. */
  timeout: 30_000,

  /* Fail the whole test suite if any test fails more than once. */
  maxFailures: 0,

  /* Retry flaky tests once in CI. */
  retries: process.env.CI ? 1 : 0,

  /* Run tests in serial within each file for deterministic Drupal state. */
  fullyParallel: false,

  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: 'playwright-report' }],
  ],

  use: {
    /** Base URL — all page.goto('/path') calls are relative to this. */
    baseURL: process.env.DRUPAL_BASE_URL || 'http://localhost',

    /** Capture screenshot on failure for easier debugging. */
    screenshot: 'only-on-failure',

    /** Capture full trace on first retry. */
    trace: 'on-first-retry',

    /** Reasonable navigation timeout. */
    navigationTimeout: 15_000,

    /** Accept self-signed TLS certificates on local dev installs. */
    ignoreHTTPSErrors: true,
  },

  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
    {
      name: 'firefox',
      use: { browserName: 'firefox' },
    },
    {
      name: 'webkit',
      use: { browserName: 'webkit' },
    },
  ],
};
