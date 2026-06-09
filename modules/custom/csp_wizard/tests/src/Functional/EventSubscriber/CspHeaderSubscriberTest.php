<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Functional\EventSubscriber;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for CspHeaderSubscriber.
 *
 * @group csp_wizard
 */
final class CspHeaderSubscriberTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['csp_wizard'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests that the Report-Only header is present by default.
   */
  public function testReportOnlyHeaderPresentByDefault(): void {
    $this->drupalGet('/');
    $headers = $this->getSession()->getResponseHeaders();

    $this->assertArrayHasKey('Content-Security-Policy-Report-Only', $headers);
    $this->assertArrayNotHasKey('Content-Security-Policy', $headers);
  }

  /**
   * Tests that switching to enforce mode changes the header name.
   */
  public function testEnforceModeWritesEnforceHeader(): void {
    $this->config('csp_wizard.settings')->set('mode', 'enforce')->save();

    $this->drupalGet('/');
    $headers = $this->getSession()->getResponseHeaders();

    $this->assertArrayHasKey('Content-Security-Policy', $headers);
    $this->assertArrayNotHasKey('Content-Security-Policy-Report-Only', $headers);
  }

  /**
   * Tests that the Reporting-Endpoints header is written when reporting is on.
   */
  public function testReportingEndpointsHeaderPresentWhenReportUriEnabled(): void {
    $this->config('csp_wizard.settings')
      ->set('report_uri_enabled', TRUE)
      ->save();

    $this->drupalGet('/');
    $headers = $this->getSession()->getResponseHeaders();

    $this->assertArrayHasKey('Reporting-Endpoints', $headers);
    $this->assertStringContainsString('/csp-wizard/report', $headers['Reporting-Endpoints'][0]);
  }

}
