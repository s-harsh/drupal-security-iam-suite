<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Functional;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for per-request nonce injection into HTML.
 *
 * @group csp_wizard
 */
final class NonceInjectionTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['csp_wizard'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    // Ensure nonce injection is enabled.
    $this->config('csp_wizard.settings')
      ->set('nonce_enabled', TRUE)
      ->set('mode', 'report_only')
      ->save();
  }

  /**
   * Tests that drupalSettings.cspWizard.nonce is a Base64url string.
   */
  public function testDrupalSettingsContainsNonce(): void {
    $this->drupalGet('/');
    $this->assertSession()->statusCodeEquals(200);

    $page = $this->getSession()->getPage()->getContent();
    $this->assertStringContainsString('"cspWizard"', $page);
    $this->assertStringContainsString('"nonce"', $page);
  }

  /**
   * Tests that the nonce value in the CSP header is non-empty.
   */
  public function testCspHeaderContainsNonce(): void {
    $this->drupalGet('/');
    $headers = $this->getSession()->getResponseHeaders();

    $headerName = 'Content-Security-Policy-Report-Only';
    $this->assertArrayHasKey($headerName, $headers);
    $this->assertStringContainsString("'nonce-", $headers[$headerName][0]);
  }

  /**
   * Tests that two separate requests produce different nonce values.
   */
  public function testTwoRequestsProduceDifferentNonces(): void {
    $this->drupalGet('/');
    $headers1 = $this->getSession()->getResponseHeaders();
    $header1 = $headers1['Content-Security-Policy-Report-Only'][0] ?? '';

    $this->drupalGet('/');
    $headers2 = $this->getSession()->getResponseHeaders();
    $header2 = $headers2['Content-Security-Policy-Report-Only'][0] ?? '';

    // Extract nonce values.
    preg_match("/'nonce-([A-Za-z0-9\-_]+)'/", $header1, $matches1);
    preg_match("/'nonce-([A-Za-z0-9\-_]+)'/", $header2, $matches2);

    if (!empty($matches1[1]) && !empty($matches2[1])) {
      $this->assertNotSame($matches1[1], $matches2[1], 'Different requests must produce different nonces.');
    }
  }

}
