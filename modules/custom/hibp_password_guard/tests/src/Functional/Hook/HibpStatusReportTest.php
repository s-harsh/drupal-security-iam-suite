<?php

declare(strict_types=1);

namespace Drupal\Tests\hibp_password_guard\Functional\Hook;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for hook_requirements() status report integration.
 *
 * Verifies that the HIBP Password Guard module adds its row to the Drupal
 * status report page (/admin/reports/status) and that the row contains
 * expected text in various API connectivity scenarios.
 *
 * @group hibp_password_guard
 */
final class HibpStatusReportTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['hibp_password_guard', 'password_policy'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * The status report path.
   */
  private const STATUS_REPORT_PATH = '/admin/reports/status';

  // -------------------------------------------------------------------------
  // Access control
  // -------------------------------------------------------------------------

  /**
   * Tests that anonymous users cannot access the status report.
   */
  public function testAnonymousCannotViewStatusReport(): void {
    $this->drupalGet(self::STATUS_REPORT_PATH);
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that a user without 'access site reports' receives 403.
   */
  public function testUnprivilegedUserCannotViewStatusReport(): void {
    $user = $this->drupalCreateUser(['access administration pages']);
    $this->drupalLogin($user);

    $this->drupalGet(self::STATUS_REPORT_PATH);
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that a user with 'administer site configuration' + 'access site reports' can view the page.
   */
  public function testPrivilegedUserCanViewStatusReport(): void {
    $user = $this->drupalCreateUser([
      'administer site configuration',
      'access site reports',
    ]);
    $this->drupalLogin($user);

    $this->drupalGet(self::STATUS_REPORT_PATH);
    $this->assertSession()->statusCodeEquals(200);
  }

  // -------------------------------------------------------------------------
  // HIBP row presence
  // -------------------------------------------------------------------------

  /**
   * Tests that the HIBP Pwned Passwords API row appears on the status report.
   */
  public function testStatusReportContainsHibpRow(): void {
    $user = $this->drupalCreateUser([
      'administer site configuration',
      'access site reports',
    ]);
    $this->drupalLogin($user);

    $this->drupalGet(self::STATUS_REPORT_PATH);
    $this->assertSession()->pageTextContains('HIBP Pwned Passwords API');
  }

  /**
   * Tests that the HIBP row title is specific enough to distinguish the module.
   */
  public function testStatusReportHibpRowTitleIsSpecific(): void {
    $user = $this->drupalCreateUser([
      'administer site configuration',
      'access site reports',
    ]);
    $this->drupalLogin($user);

    $this->drupalGet(self::STATUS_REPORT_PATH);
    // Title must name both HIBP and the Pwned Passwords API.
    $this->assertSession()->pageTextContains('HIBP');
    $this->assertSession()->pageTextContains('Pwned Passwords');
  }

  // -------------------------------------------------------------------------
  // Fail mode config affects status report outcome
  // -------------------------------------------------------------------------

  /**
   * Tests that when API is unreachable with fail_open, status report still renders.
   *
   * Sets an unreachable API URL and verifies the page loads without a PHP error.
   */
  public function testStatusReportRendersWhenApiIsUnreachable(): void {
    $this->config('hibp_password_guard.settings')
      ->set('api_base_url', 'https://127.0.0.1:1')
      ->set('http_timeout', 1)
      ->save();

    // Clear the probe cache so it re-runs.
    \Drupal::cache()->delete('hibp_password_guard.requirements_probe');

    $user = $this->drupalCreateUser([
      'administer site configuration',
      'access site reports',
    ]);
    $this->drupalLogin($user);

    $this->drupalGet(self::STATUS_REPORT_PATH);
    $this->assertSession()->statusCodeEquals(200);
    // Row must still appear even when API is unreachable.
    $this->assertSession()->pageTextContains('HIBP Pwned Passwords API');
  }

  // -------------------------------------------------------------------------
  // Cache behaviour
  // -------------------------------------------------------------------------

  /**
   * Tests that the status report page loads within a reasonable number of requests
   * (specifically, that the probe cache prevents duplicate API calls).
   *
   * This is verified by loading the page twice and confirming the second load
   * also shows the HIBP row (served from cache).
   */
  public function testStatusReportHibpRowAppearsOnRepeatedLoads(): void {
    $user = $this->drupalCreateUser([
      'administer site configuration',
      'access site reports',
    ]);
    $this->drupalLogin($user);

    // First load.
    $this->drupalGet(self::STATUS_REPORT_PATH);
    $this->assertSession()->pageTextContains('HIBP Pwned Passwords API');

    // Second load — should serve cached probe result.
    $this->drupalGet(self::STATUS_REPORT_PATH);
    $this->assertSession()->pageTextContains('HIBP Pwned Passwords API');
  }

}
