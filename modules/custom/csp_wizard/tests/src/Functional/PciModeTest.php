<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Functional;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for PCI DSS 6.4.3 compliance mode.
 *
 * @group csp_wizard
 */
final class PciModeTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['csp_wizard'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests the PCI export route returns a CSV download.
   */
  public function testPciExportReturnsCsvDownload(): void {
    $this->config('csp_wizard.settings')
      ->set('pci_mode', [
        'enabled'       => TRUE,
        'page_patterns' => ['/checkout/**'],
        'trusted_types' => FALSE,
        'export_format' => 'csv',
      ])
      ->save();

    $user = $this->drupalCreateUser(['administer csp wizard']);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/config/security/csp-wizard/pci-export');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->responseHeaderContains('Content-Type', 'text/csv');
    $this->assertSession()->responseHeaderContains('Content-Disposition', 'attachment');
  }

  /**
   * Tests the PCI export route returns a JSON download when configured.
   */
  public function testPciExportReturnsJsonDownload(): void {
    $this->config('csp_wizard.settings')
      ->set('pci_mode', [
        'enabled'       => TRUE,
        'page_patterns' => ['/checkout/**'],
        'trusted_types' => FALSE,
        'export_format' => 'json',
      ])
      ->save();

    $user = $this->drupalCreateUser(['administer csp wizard']);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/config/security/csp-wizard/pci-export');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->responseHeaderContains('Content-Type', 'application/json');
  }

}
