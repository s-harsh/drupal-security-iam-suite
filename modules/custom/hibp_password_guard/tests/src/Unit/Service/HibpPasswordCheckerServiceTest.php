<?php

declare(strict_types=1);

namespace Drupal\Tests\hibp_password_guard\Unit\Service;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\hibp_password_guard\Service\HibpApiClient;
use Drupal\hibp_password_guard\Service\HibpPasswordCheckerService;
use Drupal\hibp_password_guard\Value\HibpCheckResult;
use Drupal\hibp_password_guard\Value\HibpRangeResponse;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for HibpPasswordCheckerService.
 *
 * SHA-1 test vectors used throughout this file:
 *   "password"  -> 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
 *     prefix: 5BAA6   suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
 *
 *   "hunter2"   -> F3BBBD66A63D4BF1747940578EC3D0103530E21D
 *     prefix: F3BBB   suffix: D66A63D4BF1747940578EC3D0103530E21D
 *
 * @coversDefaultClass \Drupal\hibp_password_guard\Service\HibpPasswordCheckerService
 * @group hibp_password_guard
 */
final class HibpPasswordCheckerServiceTest extends UnitTestCase {

  // -------------------------------------------------------------------------
  // Test vectors
  // -------------------------------------------------------------------------

  private const PWNED_PASSWORD = 'password';
  private const PWNED_HASH     = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';
  private const PWNED_PREFIX   = '5BAA6';
  private const PWNED_SUFFIX   = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';
  private const PWNED_COUNT    = 3533661;

  private const SECOND_PASSWORD = 'hunter2';
  private const SECOND_PREFIX   = 'F3BBB';
  private const SECOND_SUFFIX   = 'D66A63D4BF1747940578EC3D0103530E21D';

  private const CACHE_KEY_PREFIX = 'hibp_range:';

  /**
   * HIBP range response body where PWNED_SUFFIX appears with PWNED_COUNT.
   */
  private const BODY_WITH_PWNED =
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3533661\r\nABCDEF1234567890ABCDEF1234567890ABC:5";

  /**
   * HIBP range response body that does NOT contain PWNED_SUFFIX.
   */
  private const BODY_WITHOUT_PWNED =
    "ABCDEF1234567890ABCDEF1234567890ABC:5\r\nDEFABC1234567890DEFABC1234567890DEF:2";

  // -------------------------------------------------------------------------
  // Helper factories
  // -------------------------------------------------------------------------

  /**
   * Builds a config factory mock with the given settings.
   */
  private function makeConfig(
    bool $enabled = true,
    int $cacheTtl = 86400,
    string $failMode = 'fail_open',
  ): ConfigFactoryInterface {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['enabled',   $enabled],
      ['cache_ttl', $cacheTtl],
      ['fail_mode', $failMode],
    ]);

    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')
      ->with('hibp_password_guard.settings')
      ->willReturn($config);

    return $factory;
  }

  /**
   * Builds a cache mock that always misses.
   */
  private function makeCacheMiss(): CacheBackendInterface {
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn(false);
    return $cache;
  }

  /**
   * Builds a cache mock that returns a hit with the given body string.
   */
  private function makeCacheHit(string $body): CacheBackendInterface {
    $entry = new \stdClass();
    $entry->data = $body;

    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn($entry);
    return $cache;
  }

  /**
   * Builds the service under test.
   */
  private function makeService(
    HibpApiClient $apiClient,
    CacheBackendInterface $cache,
    ConfigFactoryInterface $configFactory,
    ?LoggerInterface $logger = null,
  ): HibpPasswordCheckerService {
    return new HibpPasswordCheckerService(
      $apiClient,
      $cache,
      $configFactory,
      $logger ?? $this->createMock(LoggerInterface::class),
    );
  }

  // -------------------------------------------------------------------------
  // SHA-1 correctness sanity checks
  // -------------------------------------------------------------------------

  /**
   * @covers ::check
   */
  public function testSha1TestVectorForPasswordIsCorrect(): void {
    $hash = strtoupper(hash('sha1', self::PWNED_PASSWORD));
    $this->assertSame(self::PWNED_HASH, $hash);
    $this->assertSame(self::PWNED_PREFIX, substr($hash, 0, 5));
    $this->assertSame(self::PWNED_SUFFIX, substr($hash, 5));
    $this->assertSame(35, strlen(self::PWNED_SUFFIX));
  }

  /**
   * @covers ::check
   */
  public function testSha1TestVectorForHunter2IsCorrect(): void {
    $hash = strtoupper(hash('sha1', self::SECOND_PASSWORD));
    $this->assertSame(self::SECOND_PREFIX, substr($hash, 0, 5));
    $this->assertSame(self::SECOND_SUFFIX, substr($hash, 5));
  }

  // -------------------------------------------------------------------------
  // Module disabled
  // -------------------------------------------------------------------------

  /**
   * @covers ::check
   */
  public function testCheckSkipsApiCallWhenModuleIsDisabled(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->never())->method('fetchRange');

    $service = $this->makeService(
      $apiClient,
      $this->makeCacheMiss(),
      $this->makeConfig(enabled: false),
    );

    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertInstanceOf(HibpCheckResult::class, $result);
    $this->assertFalse($result->isPwned);
    $this->assertSame(0, $result->breachCount);
    $this->assertFalse($result->apiError);
  }

  /**
   * @covers ::check
   */
  public function testCheckSkipsCacheWhenModuleIsDisabled(): void {
    $apiClient = $this->createMock(HibpApiClient::class);

    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->expects($this->never())->method('get');

    $service = $this->makeService(
      $apiClient,
      $cache,
      $this->makeConfig(enabled: false),
    );

    $service->check(self::PWNED_PASSWORD);
  }

  // -------------------------------------------------------------------------
  // Pwned detection
  // -------------------------------------------------------------------------

  /**
   * @covers ::check
   */
  public function testCheckReturnsPwnedResultWhenSuffixFound(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: self::BODY_WITH_PWNED, statusCode: 200));

    $service = $this->makeService($apiClient, $this->makeCacheMiss(), $this->makeConfig());
    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertTrue($result->isPwned);
    $this->assertSame(self::PWNED_COUNT, $result->breachCount);
    $this->assertFalse($result->apiError);
  }

  /**
   * @covers ::check
   */
  public function testCheckReturnsNotPwnedWhenSuffixAbsent(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: self::BODY_WITHOUT_PWNED, statusCode: 200));

    $service = $this->makeService($apiClient, $this->makeCacheMiss(), $this->makeConfig());
    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertFalse($result->isPwned);
    $this->assertSame(0, $result->breachCount);
    $this->assertFalse($result->apiError);
  }

  /**
   * @covers ::check
   *
   * Suffix matching must be case-insensitive per the HIBP spec.
   */
  public function testCheckMatchesSuffixCaseInsensitively(): void {
    // Response body uses lowercase suffix.
    $lowercaseSuffix = strtolower(self::PWNED_SUFFIX);
    $body = $lowercaseSuffix . ':' . self::PWNED_COUNT;

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: $body, statusCode: 200));

    $service = $this->makeService($apiClient, $this->makeCacheMiss(), $this->makeConfig());
    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertTrue($result->isPwned);
    $this->assertSame(self::PWNED_COUNT, $result->breachCount);
  }

  /**
   * @covers ::check
   *
   * HIBP Add-Padding entries have COUNT=0 and must be ignored.
   */
  public function testCheckIgnoresPaddingEntriesWithZeroCount(): void {
    $body = implode("\r\n", [
      'PADDINGENTRY0000000000000000000000:0',
      self::PWNED_SUFFIX . ':' . self::PWNED_COUNT,
      'MOREPADDING000000000000000000000000:0',
    ]);

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: $body, statusCode: 200));

    $service = $this->makeService($apiClient, $this->makeCacheMiss(), $this->makeConfig());
    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertTrue($result->isPwned);
    $this->assertSame(self::PWNED_COUNT, $result->breachCount);
  }

  /**
   * @covers ::check
   *
   * Lines that lack a colon separator must be skipped without throwing.
   */
  public function testCheckHandlesMalformedLinesGracefully(): void {
    $body = implode("\r\n", [
      'MALFORMED_LINE_NO_COLON',
      '',
      '   ',
      self::PWNED_SUFFIX . ':' . self::PWNED_COUNT,
    ]);

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: $body, statusCode: 200));

    $service = $this->makeService($apiClient, $this->makeCacheMiss(), $this->makeConfig());
    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertTrue($result->isPwned);
    $this->assertSame(self::PWNED_COUNT, $result->breachCount);
  }

  /**
   * @covers ::check
   *
   * An empty response body must result in a not-pwned result.
   */
  public function testCheckHandlesEmptyResponseBody(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: '', statusCode: 200));

    $service = $this->makeService($apiClient, $this->makeCacheMiss(), $this->makeConfig());
    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertFalse($result->isPwned);
    $this->assertSame(0, $result->breachCount);
  }

  /**
   * @covers ::check
   *
   * Passwords with special characters must be hashed correctly.
   */
  public function testCheckWorksWithSpecialCharacterPasswords(): void {
    $specialPassword = 'P@$$w0rd!#%^&*()';
    $hash = strtoupper(hash('sha1', $specialPassword));
    $prefix = substr($hash, 0, 5);
    $suffix = substr($hash, 5);

    $body = $suffix . ':999';

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->once())
      ->method('fetchRange')
      ->with($prefix)
      ->willReturn(new HibpRangeResponse(success: true, body: $body, statusCode: 200));

    $service = $this->makeService($apiClient, $this->makeCacheMiss(), $this->makeConfig());
    $result = $service->check($specialPassword);

    $this->assertTrue($result->isPwned);
    $this->assertSame(999, $result->breachCount);
  }

  // -------------------------------------------------------------------------
  // Cache behaviour
  // -------------------------------------------------------------------------

  /**
   * @covers ::check
   */
  public function testCheckUsesCorrectCacheKeyForPrefix(): void {
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->expects($this->once())
      ->method('get')
      ->with(self::CACHE_KEY_PREFIX . self::PWNED_PREFIX)
      ->willReturn(false);

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: self::BODY_WITHOUT_PWNED, statusCode: 200));

    $service = $this->makeService($apiClient, $cache, $this->makeConfig());
    $service->check(self::PWNED_PASSWORD);
  }

  /**
   * @covers ::check
   */
  public function testCheckSkipsApiOnCacheHit(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->never())->method('fetchRange');

    $service = $this->makeService(
      $apiClient,
      $this->makeCacheHit(self::BODY_WITH_PWNED),
      $this->makeConfig(),
    );

    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertTrue($result->isPwned);
    $this->assertSame(self::PWNED_COUNT, $result->breachCount);
  }

  /**
   * @covers ::check
   */
  public function testCheckWritesApiResponseToCacheWithCorrectKey(): void {
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn(false);
    $cache->expects($this->once())
      ->method('set')
      ->with(
        self::CACHE_KEY_PREFIX . self::PWNED_PREFIX,
        self::BODY_WITHOUT_PWNED,
        $this->greaterThan(time()),
      );

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: self::BODY_WITHOUT_PWNED, statusCode: 200));

    $service = $this->makeService($apiClient, $cache, $this->makeConfig(cacheTtl: 86400));
    $service->check(self::PWNED_PASSWORD);
  }

  /**
   * @covers ::check
   */
  public function testCheckCacheExpiryIsCurrentTimePlusTtl(): void {
    $ttl = 3600;
    $beforeCall = time();

    $capturedExpiry = 0;
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn(false);
    $cache->method('set')
      ->willReturnCallback(function (string $key, string $data, int $expiry) use (&$capturedExpiry): void {
        $capturedExpiry = $expiry;
      });

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: self::BODY_WITHOUT_PWNED, statusCode: 200));

    $service = $this->makeService($apiClient, $cache, $this->makeConfig(cacheTtl: $ttl));
    $service->check(self::PWNED_PASSWORD);

    $afterCall = time();

    $this->assertGreaterThanOrEqual($beforeCall + $ttl, $capturedExpiry);
    $this->assertLessThanOrEqual($afterCall + $ttl, $capturedExpiry);
  }

  /**
   * @covers ::check
   */
  public function testCheckDoesNotWriteCacheWhenTtlIsZero(): void {
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn(false);
    $cache->expects($this->never())->method('set');

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: self::BODY_WITHOUT_PWNED, statusCode: 200));

    $service = $this->makeService($apiClient, $cache, $this->makeConfig(cacheTtl: 0));
    $service->check(self::PWNED_PASSWORD);
  }

  /**
   * @covers ::check
   *
   * When bypassCache=true, get() must not be called.
   */
  public function testCheckSkipsCacheReadWhenBypassFlagIsSet(): void {
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->expects($this->never())->method('get');

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->once())
      ->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: self::BODY_WITHOUT_PWNED, statusCode: 200));

    $service = $this->makeService($apiClient, $cache, $this->makeConfig());
    $service->check(self::PWNED_PASSWORD, bypassCache: true);
  }

  /**
   * @covers ::check
   *
   * Even when cache is bypassed, a successful response should still be cached.
   */
  public function testCheckStillWritesCacheWhenBypassFlagIsSet(): void {
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->expects($this->never())->method('get');
    $cache->expects($this->once())->method('set');

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: self::BODY_WITHOUT_PWNED, statusCode: 200));

    $service = $this->makeService($apiClient, $cache, $this->makeConfig(cacheTtl: 3600));
    $service->check(self::PWNED_PASSWORD, bypassCache: true);
  }

  // -------------------------------------------------------------------------
  // API failure and degradation modes
  // -------------------------------------------------------------------------

  /**
   * @covers ::check
   */
  public function testCheckFailOpenReturnsNotPwnedWithApiErrorFlag(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: false, statusCode: 0, errorMessage: 'ConnectException'));

    $service = $this->makeService(
      $apiClient,
      $this->makeCacheMiss(),
      $this->makeConfig(failMode: 'fail_open'),
    );

    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertFalse($result->isPwned);
    $this->assertSame(0, $result->breachCount);
    $this->assertTrue($result->apiError);
  }

  /**
   * @covers ::check
   */
  public function testCheckFailClosedReturnsPwnedWithApiErrorFlag(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: false, statusCode: 0, errorMessage: 'ConnectException'));

    $service = $this->makeService(
      $apiClient,
      $this->makeCacheMiss(),
      $this->makeConfig(failMode: 'fail_closed'),
    );

    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertTrue($result->isPwned);
    $this->assertSame(0, $result->breachCount);
    $this->assertTrue($result->apiError);
  }

  /**
   * @covers ::check
   */
  public function testCheckFailClosedPreservesErrorType(): void {
    $errorType = 'GuzzleHttp\Exception\ConnectException';

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: false, statusCode: 0, errorMessage: $errorType));

    $service = $this->makeService(
      $apiClient,
      $this->makeCacheMiss(),
      $this->makeConfig(failMode: 'fail_closed'),
    );

    $result = $service->check(self::PWNED_PASSWORD);

    $this->assertSame($errorType, $result->errorType);
  }

  /**
   * @covers ::check
   */
  public function testCheckDoesNotWriteCacheOnApiFailure(): void {
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn(false);
    $cache->expects($this->never())->method('set');

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: false, statusCode: 0, errorMessage: 'ConnectException'));

    $service = $this->makeService($apiClient, $cache, $this->makeConfig());
    $service->check(self::PWNED_PASSWORD);
  }

  /**
   * @covers ::check
   */
  public function testCheckLogsNoticeOnApiFailure(): void {
    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())
      ->method('notice')
      ->with(
        $this->stringContains('HIBP API unavailable'),
        $this->arrayHasKey('@mode'),
      );

    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: false, statusCode: 0, errorMessage: 'ConnectException'));

    $service = $this->makeService(
      $apiClient,
      $this->makeCacheMiss(),
      $this->makeConfig(),
      $logger,
    );

    $service->check(self::PWNED_PASSWORD);
  }

  // -------------------------------------------------------------------------
  // Correct prefix is passed to the API client
  // -------------------------------------------------------------------------

  /**
   * @covers ::check
   *
   * The API client must receive exactly the first 5 uppercase hex chars of SHA-1.
   */
  public function testCheckPassesCorrectPrefixToApiClient(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->once())
      ->method('fetchRange')
      ->with(self::PWNED_PREFIX)
      ->willReturn(new HibpRangeResponse(success: true, body: self::BODY_WITHOUT_PWNED, statusCode: 200));

    $service = $this->makeService($apiClient, $this->makeCacheMiss(), $this->makeConfig());
    $service->check(self::PWNED_PASSWORD);
  }

  /**
   * @covers ::check
   *
   * Verifies that a second distinct password sends the correct, different prefix.
   */
  public function testCheckPassesCorrectPrefixForSecondTestVector(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->expects($this->once())
      ->method('fetchRange')
      ->with(self::SECOND_PREFIX)
      ->willReturn(new HibpRangeResponse(success: true, body: '', statusCode: 200));

    $service = $this->makeService($apiClient, $this->makeCacheMiss(), $this->makeConfig());
    $service->check(self::SECOND_PASSWORD);
  }

  // -------------------------------------------------------------------------
  // Return type contract
  // -------------------------------------------------------------------------

  /**
   * @covers ::check
   */
  public function testCheckAlwaysReturnsHibpCheckResultInstance(): void {
    $apiClient = $this->createMock(HibpApiClient::class);
    $apiClient->method('fetchRange')
      ->willReturn(new HibpRangeResponse(success: true, body: '', statusCode: 200));

    $service = $this->makeService($apiClient, $this->makeCacheMiss(), $this->makeConfig());

    $this->assertInstanceOf(HibpCheckResult::class, $service->check('anypassword'));
    $this->assertInstanceOf(HibpCheckResult::class, $service->check('', false));
  }

}
