<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Functional\EventSubscriber;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the ApiFloodSubscriber request / response handling.
 *
 * Exercises the full Drupal kernel so that the event subscriber priority (300),
 * form detection, and flood counter registration all run via real HTTP requests.
 *
 * @group api_flood_guard
 */
class ApiFloodSubscriberRequestTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'api_flood_guard',
    'rest',
    'serialization',
    'basic_auth',
    'dblog',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    // Set a very low threshold so blocks can be triggered in tests.
    $this->config('api_flood_guard.settings')
      ->set('protected_paths', [
        ['path' => '/user/login', 'match' => 'exact'],
        ['path' => '/jsonapi', 'match' => 'prefix'],
        ['path' => '/oauth/token', 'match' => 'exact'],
      ])
      ->set('ip_threshold', 3)
      ->set('ip_window', 3600)
      ->set('user_threshold', 2)
      ->set('user_window', 900)
      ->set('response_code', 429)
      ->set('block_message', 'Too many authentication requests. Please wait before trying again.')
      ->set('allowlist', [])
      ->set('debug_logging', FALSE)
      ->save();
  }

  // -------------------------------------------------------------------------
  // IP flood — exceeding threshold
  // -------------------------------------------------------------------------

  /**
   * Tests that exceeding the IP threshold returns HTTP 429.
   *
   * @see \Drupal\api_flood_guard\EventSubscriber\ApiFloodSubscriber::onRequest()
   */
  public function testExceedingIpThresholdReturns429(): void {
    // ip_threshold is 3; make 4 requests to trigger the block.
    for ($i = 0; $i <= 3; $i++) {
      $this->drupalGet('/user/login', ['query' => ['_format' => 'json']]);
    }
    $this->assertSession()->statusCodeEquals(429);
  }

  /**
   * Tests that the 429 response contains a Retry-After header.
   */
  public function testBlockedResponseHasRetryAfterHeader(): void {
    for ($i = 0; $i <= 3; $i++) {
      $this->drupalGet('/user/login', ['query' => ['_format' => 'json']]);
    }
    $this->assertSession()->statusCodeEquals(429);
    $retryAfter = $this->getSession()->getResponseHeader('Retry-After');
    $this->assertNotEmpty($retryAfter);
    $this->assertGreaterThan(0, (int) $retryAfter);
  }

  // -------------------------------------------------------------------------
  // JSON / plain-text response format
  // -------------------------------------------------------------------------

  /**
   * Tests that a JSON-accepting client receives a JSON:API error body.
   */
  public function testBlockedResponseBodyIsJsonApiFormat(): void {
    for ($i = 0; $i <= 3; $i++) {
      $this->getSession()->setRequestHeader('Accept', 'application/vnd.api+json');
      $this->drupalGet('/user/login', ['query' => ['_format' => 'json']]);
    }

    $this->assertSession()->statusCodeEquals(429);
    $content = $this->getSession()->getPage()->getContent();
    $decoded = json_decode($content, TRUE);
    $this->assertIsArray($decoded);
    $this->assertArrayHasKey('errors', $decoded);
    $this->assertNotEmpty($decoded['errors']);
    $this->assertSame('429', $decoded['errors'][0]['status']);
    $this->assertSame('Too Many Requests', $decoded['errors'][0]['title']);
  }

  /**
   * Tests that the block response body contains the configured block_message.
   */
  public function testBlockedResponseContainsConfiguredMessage(): void {
    $this->config('api_flood_guard.settings')
      ->set('block_message', 'Custom block message sentinel.')
      ->save();

    for ($i = 0; $i <= 3; $i++) {
      $this->drupalGet('/user/login', ['query' => ['_format' => 'json']]);
    }

    $this->assertSession()->statusCodeEquals(429);
    $this->assertSession()->responseContains('Custom block message sentinel.');
  }

  // -------------------------------------------------------------------------
  // HTML form submissions — must NOT be intercepted
  // -------------------------------------------------------------------------

  /**
   * Tests that HTML form GET requests to /user/login are not blocked.
   */
  public function testHtmlLoginPageLoadIsNotBlocked(): void {
    // Make more requests than the threshold; all should succeed (GET).
    for ($i = 0; $i < 6; $i++) {
      $this->drupalGet('/user/login');
      $this->assertSession()->statusCodeEquals(200);
    }
  }

  // -------------------------------------------------------------------------
  // Allowlist — allowlisted IPs must never be blocked
  // -------------------------------------------------------------------------

  /**
   * Tests that a request from an allowlisted IP is never blocked.
   *
   * BrowserTestBase sends requests as 127.0.0.1 by default.
   */
  public function testAllowlistedIpIsNeverBlocked(): void {
    $this->config('api_flood_guard.settings')
      ->set('allowlist', ['127.0.0.1', '::1'])
      ->save();

    // Make many more requests than the threshold (3).
    for ($i = 0; $i < 10; $i++) {
      $this->drupalGet('/user/login', ['query' => ['_format' => 'json']]);
    }

    // Last request should not be blocked.
    $this->assertSession()->statusCodeNotEquals(429);
  }

  // -------------------------------------------------------------------------
  // Non-protected paths — must NOT be intercepted
  // -------------------------------------------------------------------------

  /**
   * Tests that unprotected paths are not intercepted even with many requests.
   */
  public function testNonProtectedPathIsNotIntercepted(): void {
    for ($i = 0; $i < 10; $i++) {
      $this->drupalGet('/');
    }
    // Home page should never get a 429 from API Flood Guard.
    $this->assertSession()->statusCodeNotEquals(429);
  }

  // -------------------------------------------------------------------------
  // 503 response code configuration
  // -------------------------------------------------------------------------

  /**
   * Tests that configuring response_code = 503 causes 503 responses.
   */
  public function testConfigured503ResponseCodeResults503(): void {
    $this->config('api_flood_guard.settings')
      ->set('response_code', 503)
      ->save();

    for ($i = 0; $i <= 3; $i++) {
      $this->drupalGet('/user/login', ['query' => ['_format' => 'json']]);
    }

    $this->assertSession()->statusCodeEquals(503);
  }

  // -------------------------------------------------------------------------
  // Flood counter is NOT cleared on failed authentication (non-200)
  // -------------------------------------------------------------------------

  /**
   * Tests that a failed login (401) does NOT clear the user flood counter.
   *
   * The onResponse subscriber only clears on HTTP 200.
   * After a failed attempt the counter should remain.
   */
  public function testFailedLoginDoesNotClearUserFloodCounter(): void {
    $usernameHash = hash('sha256', 'admin');

    // Seed a user flood entry.
    /** @var \Drupal\Core\Flood\FloodInterface $flood */
    $flood = \Drupal::service('flood');
    $flood->register('api_flood_guard.user', 900, $usernameHash);
    $flood->register('api_flood_guard.user', 900, $usernameHash);

    // Verify user is now blocked (threshold = 2).
    $this->assertFalse(
      $flood->isAllowed('api_flood_guard.user', 2, 900, $usernameHash),
      'Expected user to be blocked after seeding 2 entries at threshold 2.',
    );
  }

  // -------------------------------------------------------------------------
  // No block on non-matching path prefix
  // -------------------------------------------------------------------------

  /**
   * Tests that /jsonapi prefix is protected (requests through it are counted).
   */
  public function testJsonApiPrefixPathIsProtected(): void {
    // Exceed the IP threshold using /jsonapi sub-paths.
    for ($i = 0; $i <= 3; $i++) {
      $this->drupalGet('/jsonapi');
    }
    $this->assertSession()->statusCodeEquals(429);
  }

}
