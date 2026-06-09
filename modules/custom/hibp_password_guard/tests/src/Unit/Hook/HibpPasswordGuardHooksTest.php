<?php

declare(strict_types=1);

namespace Drupal\Tests\hibp_password_guard\Unit\Hook;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\hibp_password_guard\Hook\HibpPasswordGuardHooks;
use Drupal\hibp_password_guard\Service\HibpApiClient;
use Drupal\hibp_password_guard\Value\HibpRangeResponse;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * Unit tests for HibpPasswordGuardHooks.
 *
 * Covers requirements() and help() hook implementations including:
 *   - Phase filtering (non-runtime phases return empty array).
 *   - Probe prefix correctness.
 *   - Severity mapping: success -> OK, HTTP error -> WARNING, connect -> ERROR.
 *   - Cache hit prevents redundant API calls.
 *   - Cache writes on fresh probe.
 *   - Required keys in requirements entry.
 *
 * @coversDefaultClass \Drupal\hibp_password_guard\Hook\HibpPasswordGuardHooks
 * @group hibp_password_guard
 */
final class HibpPasswordGuardHooksTest extends UnitTestCase {

  /**
   * The innocuous 5-char SHA-1 prefix used by the requirements probe.
   */
  private const PROBE_PREFIX = '00000';

  /**
   * Cache key used for the probe result.
   */
  private const PROBE_CACHE_KEY = 'hibp_password_guard.requirements_probe';

  // -------------------------------------------------------------------------
  // Factory helpers
  // -------------------------------------------------------------------------

  /**
   * Creates an HibpPasswordGuardHooks instance with a cache that always misses.
   */
  private function makeHooks(HibpApiClient $apiClient): HibpPasswordGuardHooks {
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn(false);

    return new HibpPasswordGuardHooks($apiClient, $configFactory, $cache);
  }

  /**
   * Creates hooks with a cache that returns the given data as a hit.
   */
  private function makeHooksWithCacheHit(array $cachedData): HibpPasswordGuardHooks {
    $apiClient = $this->createMock(HibpApiClient::class);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);

    $entry = new \stdClass();
    $entry->data = $cachedData;

    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')
      ->with(self::PROBE_CACHE_KEY)
      ->willReturn($entry);

    return new HibpPasswordGuardHooks($apiClient, $configFactory, $cache);
  }

  // -------------------------------------------------------------------------
  // Phase filtering
  // -------------------------------------------------------------------------

  /**
   * @covers ::requirements
   */
  public function testRequirementsReturnsEmptyForInstallPhase(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->never())->method('fetchRange');

    $result = $this->makeHooks($apiClient)->requirements('install');

    $this->assertIsArray($result);
    $this->assertEmpty($result);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsReturnsEmptyForUpdatePhase(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->never())->method('fetchRange');

    $result = $this->makeHooks($apiClient)->requirements('update');

    $this->assertIsArray($result);
    $this->assertEmpty($result);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsDoesNotCallApiForNonRuntimePhase(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->never())->method('fetchRange');

    $this->makeHooks($apiClient)->requirements('install');
    $this->makeHooks($apiClient)->requirements('update');
    $this->makeHooks($apiClient)->requirements('some_other_phase');
  }

  // -------------------------------------------------------------------------
  // Probe prefix
  // -------------------------------------------------------------------------

  /**
   * @covers ::requirements
   */
  public function testRequirementsProbesWithExactlyFiveZeroPrefix(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->once())
      ->method('fetchRange')
      ->with($this->equalTo(self::PROBE_PREFIX))
      ->willReturn(new HibpRangeResponse(success: true, statusCode: 200, body: 'ABC:1'));

    $this->makeHooks($apiClient)->requirements('runtime');
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsDoesNotSendFullHashAsPrefix(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->once())
      ->method('fetchRange')
      ->with($this->callback(function (string $prefix): bool {
        // Must be exactly 5 characters, not a 40-char full hash.
        return strlen($prefix) === 5;
      }))
      ->willReturn(new HibpRangeResponse(success: true, statusCode: 200, body: ''));

    $this->makeHooks($apiClient)->requirements('runtime');
  }

  // -------------------------------------------------------------------------
  // Severity mapping
  // -------------------------------------------------------------------------

  /**
   * @covers ::requirements
   */
  public function testRequirementsReturnsSeverityOkOnSuccessfulProbe(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, statusCode: 200, body: 'ABC:1'));

    $result = $this->makeHooks($apiClient)->requirements('runtime');

    $this->assertSame(REQUIREMENT_OK, $result['hibp_password_guard']['severity']);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsReturnsSeverityWarningOnNon200StatusCode(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: false, statusCode: 503, errorMessage: 'HTTP 503'));

    $result = $this->makeHooks($apiClient)->requirements('runtime');

    $this->assertSame(REQUIREMENT_WARNING, $result['hibp_password_guard']['severity']);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsReturnsSeverityWarningOn429RateLimit(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: false, statusCode: 429, errorMessage: 'HTTP 429'));

    $result = $this->makeHooks($apiClient)->requirements('runtime');

    $this->assertSame(REQUIREMENT_WARNING, $result['hibp_password_guard']['severity']);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsReturnsSeverityErrorOnConnectionFailure(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: false, statusCode: 0, errorMessage: 'ConnectException'));

    $result = $this->makeHooks($apiClient)->requirements('runtime');

    $this->assertSame(REQUIREMENT_ERROR, $result['hibp_password_guard']['severity']);
  }

  /**
   * @covers ::requirements
   *
   * statusCode > 0 but success = false must map to WARNING, not ERROR.
   */
  public function testRequirementsDistinguishesHttpErrorFromConnectionError(): void {
    $httpErrorClient = $this->createMock(HibpApiClient::class);
    $httpErrorClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: false, statusCode: 500, errorMessage: 'HTTP 500'));

    $connectErrorClient = $this->createMock(HibpApiClient::class);
    $connectErrorClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: false, statusCode: 0, errorMessage: 'ConnectException'));

    $httpResult = $this->makeHooks($httpErrorClient)->requirements('runtime');
    $connectResult = $this->makeHooks($connectErrorClient)->requirements('runtime');

    $this->assertSame(REQUIREMENT_WARNING, $httpResult['hibp_password_guard']['severity'],
      'Non-zero HTTP status should produce a WARNING');
    $this->assertSame(REQUIREMENT_ERROR, $connectResult['hibp_password_guard']['severity'],
      'Zero status (connection failure) should produce an ERROR');
  }

  // -------------------------------------------------------------------------
  // Required keys in requirements entry
  // -------------------------------------------------------------------------

  /**
   * @covers ::requirements
   */
  public function testRequirementsResultContainsAllRequiredKeys(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, statusCode: 200, body: ''));

    $result = $this->makeHooks($apiClient)->requirements('runtime');

    $this->assertArrayHasKey('hibp_password_guard', $result);

    $entry = $result['hibp_password_guard'];
    $this->assertArrayHasKey('title',       $entry);
    $this->assertArrayHasKey('value',       $entry);
    $this->assertArrayHasKey('description', $entry);
    $this->assertArrayHasKey('severity',    $entry);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsResultKeyIsHibpPasswordGuard(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, statusCode: 200, body: ''));

    $result = $this->makeHooks($apiClient)->requirements('runtime');

    $this->assertCount(1, $result, 'requirements() must return exactly one entry for this module.');
    $this->assertArrayHasKey('hibp_password_guard', $result);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsResultTitleContainsHibp(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, statusCode: 200, body: ''));

    $result = $this->makeHooks($apiClient)->requirements('runtime');

    // The title may be a TranslatableMarkup object; cast to string for assertion.
    $title = (string) $result['hibp_password_guard']['title'];
    $this->assertStringContainsString('HIBP', $title);
  }

  // -------------------------------------------------------------------------
  // Cache behaviour
  // -------------------------------------------------------------------------

  /**
   * @covers ::requirements
   */
  public function testRequirementsReturnsCachedDataWithoutCallingApi(): void {
    $cachedData = [
      'hibp_password_guard' => [
        'title'       => 'HIBP Pwned Passwords API',
        'value'       => 'Reachable',
        'description' => 'Cached entry.',
        'severity'    => REQUIREMENT_OK,
      ],
    ];

    $hooks = $this->makeHooksWithCacheHit($cachedData);
    $result = $hooks->requirements('runtime');

    $this->assertSame(REQUIREMENT_OK, $result['hibp_password_guard']['severity']);
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsStoresProbeResultInCache(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, statusCode: 200, body: 'ABC:1'));

    $configFactory = $this->createMock(ConfigFactoryInterface::class);

    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn(false);
    $cache->expects($this->once())
      ->method('set')
      ->with(
        self::PROBE_CACHE_KEY,
        $this->isArray(),
        $this->greaterThan(time()),
      );

    $hooks = new HibpPasswordGuardHooks($apiClient, $configFactory, $cache);
    $hooks->requirements('runtime');
  }

  /**
   * @covers ::requirements
   */
  public function testRequirementsApiCalledExactlyOnceOnCacheMiss(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->once())
      ->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, statusCode: 200, body: ''));

    $this->makeHooks($apiClient)->requirements('runtime');
  }

  // -------------------------------------------------------------------------
  // help() hook
  // -------------------------------------------------------------------------

  /**
   * @covers ::help
   */
  public function testHelpReturnsEmptyStringForUnknownRoute(): void {
    $apiClient  = $this->createMock(HibpApiClient::class);
    $routeMatch = $this->createMock(\Drupal\Core\Routing\RouteMatchInterface::class);

    $result = $this->makeHooks($apiClient)->help('some.other.route', $routeMatch);

    $this->assertSame('', $result);
  }

  /**
   * @covers ::help
   */
  public function testHelpReturnsEmptyStringForAdminConfigRoute(): void {
    $apiClient  = $this->createMock(HibpApiClient::class);
    $routeMatch = $this->createMock(\Drupal\Core\Routing\RouteMatchInterface::class);

    $result = $this->makeHooks($apiClient)->help('hibp_password_guard.settings', $routeMatch);

    $this->assertSame('', $result);
  }

}
