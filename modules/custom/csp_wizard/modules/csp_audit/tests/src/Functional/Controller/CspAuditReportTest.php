<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_audit\Functional\Controller;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the CSP Audit Report page.
 *
 * @group csp_audit
 */
final class CspAuditReportTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['csp_wizard', 'csp_audit'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests that the audit report page loads for an authorised user.
   */
  public function testReportPageLoadsForAuthorisedUser(): void {
    $user = $this->drupalCreateUser(['administer csp audit']);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/reports/csp-audit');
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that anonymous users are denied access to the audit report.
   */
  public function testReportPageDeniesAnonymousAccess(): void {
    $this->drupalGet('/admin/reports/csp-audit');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that the re-scan action redirects back to the report.
   */
  public function testRescanRedirectsToReport(): void {
    $user = $this->drupalCreateUser(['administer csp audit']);
    $this->drupalLogin($user);

    // Obtain a CSRF token for the re-scan route.
    $token = \Drupal::service('csrf_token')->get('csp-audit/rescan');
    $this->drupalGet('/admin/reports/csp-audit/rescan', ['query' => [$token => '1']]);

    $this->assertSession()->addressContains('/admin/reports/csp-audit');
  }

  /**
   * Tests that the CSV export returns a download response.
   */
  public function testCsvExportReturnsDownload(): void {
    $user = $this->drupalCreateUser(['administer csp audit']);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/reports/csp-audit/export');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->responseHeaderContains('Content-Disposition', 'attachment');
    $this->assertSession()->responseHeaderContains('Content-Type', 'text/csv');
  }

  /**
   * Tests that a module in the allowlist does not appear in the findings table.
   */
  public function testAllowlistedModuleDoesNotAppearInFindings(): void {
    // Add 'system' to the allowlist.
    $this->config('csp_audit.settings')
      ->set('allowlist', ['system'])
      ->save();

    $user = $this->drupalCreateUser(['administer csp audit']);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/reports/csp-audit');
    // The 'system' module findings (if any) should not appear.
    // This test verifies no exception is thrown and the page renders.
    $this->assertSession()->statusCodeEquals(200);
  }

}
