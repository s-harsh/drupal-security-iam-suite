<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Functional\Controller;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the CSP Report Controller endpoint.
 *
 * @group csp_wizard
 */
final class CspReportControllerTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['csp_wizard', 'dblog'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Valid CSP Level 2 csp-report payload.
   */
  private function buildCspReportPayload(string $blockedUri = 'https://evil.example.com/malicious.js'): string {
    return json_encode([
      'csp-report' => [
        'document-uri'       => 'https://example.com/page',
        'violated-directive' => 'script-src',
        'blocked-uri'        => $blockedUri,
        'source-file'        => 'https://example.com/page',
        'line-number'        => 42,
        'column-number'      => 7,
        'script-sample'      => '',
        'status-code'        => 200,
        'disposition'        => 'report',
      ],
    ]);
  }

  /**
   * Tests that a valid CSP Level 2 report returns HTTP 204.
   */
  public function testValidCspReportReturns204(): void {
    $client = $this->getHttpClient();
    $url = $this->buildUrl('/csp-wizard/report');

    $response = $client->request('POST', $url, [
      'headers' => ['Content-Type' => 'application/csp-report'],
      'body'    => $this->buildCspReportPayload(),
      'http_errors' => FALSE,
    ]);

    $this->assertSame(204, $response->getStatusCode());
  }

  /**
   * Tests that a body exceeding 4 KB returns HTTP 413.
   */
  public function testOversizedBodyReturns413(): void {
    $client = $this->getHttpClient();
    $url = $this->buildUrl('/csp-wizard/report');

    $response = $client->request('POST', $url, [
      'headers'     => ['Content-Type' => 'application/csp-report'],
      'body'        => str_repeat('x', 5000),
      'http_errors' => FALSE,
    ]);

    $this->assertSame(413, $response->getStatusCode());
  }

  /**
   * Tests that malformed JSON returns HTTP 400.
   */
  public function testMalformedJsonReturns400(): void {
    $client = $this->getHttpClient();
    $url = $this->buildUrl('/csp-wizard/report');

    $response = $client->request('POST', $url, [
      'headers'     => ['Content-Type' => 'application/csp-report'],
      'body'        => 'NOT_VALID_JSON{{',
      'http_errors' => FALSE,
    ]);

    $this->assertSame(400, $response->getStatusCode());
  }

  /**
   * Tests that a Reporting API Level 1 payload is accepted.
   */
  public function testReportingApiLevel1PayloadIsAccepted(): void {
    $client = $this->getHttpClient();
    $url = $this->buildUrl('/csp-wizard/report');

    $payload = json_encode([
      [
        'type' => 'csp-violation',
        'url'  => 'https://example.com/page',
        'body' => [
          'effectiveDirective' => 'script-src',
          'blockedURL'         => 'https://blocked.example.com/script.js',
          'disposition'        => 'enforce',
        ],
      ],
    ]);

    $response = $client->request('POST', $url, [
      'headers'     => ['Content-Type' => 'application/reports+json'],
      'body'        => $payload,
      'http_errors' => FALSE,
    ]);

    $this->assertSame(204, $response->getStatusCode());
  }

  /**
   * Tests that exceeded flood limit returns HTTP 429.
   */
  public function testFloodLimitReturns429(): void {
    // Set a very low flood limit.
    $this->config('csp_wizard.settings')
      ->set('flood_limit', 2)
      ->set('flood_window', 60)
      ->save();

    $client = $this->getHttpClient();
    $url = $this->buildUrl('/csp-wizard/report');

    $body = $this->buildCspReportPayload();
    $options = [
      'headers'     => ['Content-Type' => 'application/csp-report'],
      'body'        => $body,
      'http_errors' => FALSE,
    ];

    // First two should succeed.
    $client->request('POST', $url, $options);
    $client->request('POST', $url, $options);

    // Third should be rate-limited.
    $response = $client->request('POST', $url, $options);
    $this->assertSame(429, $response->getStatusCode());
  }

}
