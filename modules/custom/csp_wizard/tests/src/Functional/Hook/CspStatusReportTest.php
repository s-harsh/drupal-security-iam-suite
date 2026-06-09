<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Functional\Hook;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for CSP Wizard entries in the Drupal status report.
 *
 * @group csp_wizard
 */
final class CspStatusReportTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['csp_wizard', 'dblog'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests that the CSP Wizard row appears in the status report.
   */
  public function testStatusReportContainsCspWizardRow(): void {
    $admin = $this->drupalCreateUser(['administer site configuration']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports/status');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('CSP Wizard');
  }

  /**
   * Tests that the CSP Violations row appears in the status report.
   */
  public function testStatusReportContainsCspViolationsRow(): void {
    $admin = $this->drupalCreateUser(['administer site configuration']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports/status');
    $this->assertSession()->pageTextContains('CSP Violations');
  }

}
