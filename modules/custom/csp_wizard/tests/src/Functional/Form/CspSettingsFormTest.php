<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Functional\Form;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the CSP Wizard settings form.
 *
 * @group csp_wizard
 */
final class CspSettingsFormTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['csp_wizard', 'dblog'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests that the settings form renders for an authorised user.
   */
  public function testSettingsFormRendersForAuthorisedUser(): void {
    $user = $this->drupalCreateUser(['administer csp wizard']);
    $this->drupalLogin($user);
    $this->drupalGet('/admin/config/security/csp-wizard');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->fieldExists('mode');
  }

  /**
   * Tests that anonymous users are denied access to the settings form.
   */
  public function testSettingsFormDeniesAnonymousAccess(): void {
    $this->drupalGet('/admin/config/security/csp-wizard');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests submitting a valid SIEM URL saves the configuration correctly.
   */
  public function testSubmitValidSiemUrlSavesConfig(): void {
    $user = $this->drupalCreateUser(['administer csp wizard']);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/config/security/csp-wizard');
    $this->submitForm([
      'mode'              => 'report_only',
      'nonce_enabled'     => TRUE,
      'nonce_bits'        => 256,
      'report_uri_enabled' => TRUE,
      'report_siem_url'   => 'https://siem.example.com/csp',
      'flood_limit'       => 60,
      'flood_window'      => 60,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $savedUrl = $this->config('csp_wizard.settings')->get('report_siem_url');
    $this->assertSame('https://siem.example.com/csp', $savedUrl);
  }

  /**
   * Tests that an HTTP SIEM URL triggers a validation error.
   */
  public function testSubmitHttpSiemUrlTriggersValidationError(): void {
    $user = $this->drupalCreateUser(['administer csp wizard']);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/config/security/csp-wizard');
    $this->submitForm([
      'mode'            => 'report_only',
      'report_siem_url' => 'http://siem.example.com/csp',
      'flood_limit'     => 60,
      'flood_window'    => 60,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The SIEM webhook URL must use HTTPS.');
  }

  /**
   * Tests that users without the permission are denied access.
   */
  public function testSettingsFormDeniesUnprivilegedUser(): void {
    $user = $this->drupalCreateUser(['access content']);
    $this->drupalLogin($user);
    $this->drupalGet('/admin/config/security/csp-wizard');
    $this->assertSession()->statusCodeEquals(403);
  }

}
