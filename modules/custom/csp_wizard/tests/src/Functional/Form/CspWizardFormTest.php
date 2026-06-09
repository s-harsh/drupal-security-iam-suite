<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Functional\Form;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the six-step CSP Policy Wizard form.
 *
 * @group csp_wizard
 */
final class CspWizardFormTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['csp_wizard'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Runs through all six wizard steps and verifies the configuration is saved.
   */
  public function testWizardCompleteFlow(): void {
    $user = $this->drupalCreateUser(['administer csp wizard']);
    $this->drupalLogin($user);

    // Step 1: mode selection.
    $this->drupalGet('/admin/config/security/csp-wizard/wizard');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('Step 1');

    $this->submitForm(['step1[mode]' => 'report_only'], 'Next');
    $this->assertSession()->pageTextContains('Step 2');

    // Step 2: select GTM and Stripe.
    $this->submitForm([
      'step2[gtm]'    => TRUE,
      'step2[stripe]' => TRUE,
    ], 'Next');
    $this->assertSession()->pageTextContains('Step 3');

    // Step 3: nonce settings.
    $this->submitForm([
      'step3[nonce_enabled]' => TRUE,
      'step3[nonce_bits]'    => 256,
    ], 'Next');
    $this->assertSession()->pageTextContains('Step 4');

    // Step 4: violation reporting — no SIEM.
    $this->submitForm([
      'step4[report_uri_enabled]' => TRUE,
      'step4[report_siem_url]'    => '',
      'step4[flood_limit]'        => 60,
      'step4[flood_window]'       => 60,
    ], 'Next');
    $this->assertSession()->pageTextContains('Step 5');

    // Step 5: no PCI mode.
    $this->submitForm(['step5[pci_enabled]' => FALSE], 'Next');
    $this->assertSession()->pageTextContains('Step 6');

    // Step 6: verify preview contains GTM and Stripe origins.
    $this->assertSession()->pageTextContains('googletagmanager.com');
    $this->assertSession()->pageTextContains('js.stripe.com');

    // Save.
    $this->submitForm([], 'Save Configuration');
    $this->assertSession()->pageTextContains('CSP Wizard configuration has been saved.');

    // Verify saved config.
    $config = $this->config('csp_wizard.settings');
    $this->assertSame('report_only', $config->get('mode'));
    $this->assertTrue((bool) $config->get('services')['gtm']);
    $this->assertTrue((bool) $config->get('services')['stripe']);
  }

  /**
   * Tests that the Back button returns to the previous step with values intact.
   */
  public function testBackButtonPreservesValuesAcrossSteps(): void {
    $user = $this->drupalCreateUser(['administer csp wizard']);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/config/security/csp-wizard/wizard');

    // Step 1: proceed to step 2.
    $this->submitForm(['step1[mode]' => 'enforce'], 'Next');
    $this->assertSession()->pageTextContains('Step 2');

    // Step 2: check GTM and proceed to step 3.
    $this->submitForm(['step2[gtm]' => TRUE], 'Next');
    $this->assertSession()->pageTextContains('Step 3');

    // Go back to step 2.
    $this->submitForm([], 'Back');
    $this->assertSession()->pageTextContains('Step 2');
  }

  /**
   * Tests that custom domain validation rejects invalid patterns.
   */
  public function testInvalidCustomDomainIsRejected(): void {
    $user = $this->drupalCreateUser(['administer csp wizard']);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/config/security/csp-wizard/wizard');
    $this->submitForm(['step1[mode]' => 'report_only'], 'Next');

    $this->submitForm([
      'step2[custom_domains]' => "javascript:alert(1)\nvalid.example.com",
    ], 'Next');

    $this->assertSession()->pageTextContains('Invalid custom domain');
  }

}
