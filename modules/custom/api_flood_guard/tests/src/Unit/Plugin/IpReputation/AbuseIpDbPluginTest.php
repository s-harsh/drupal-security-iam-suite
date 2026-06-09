<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Unit\Plugin\IpReputation;

use Drupal\api_flood_guard\Plugin\IpReputation\AbuseIpDb;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Tests\UnitTestCase;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface as GuzzleRequestInterface;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for the AbuseIpDb IP reputation plugin.
 *
 * @group api_flood_guard
 * @coversDefaultClass \Drupal\api_flood_guard\Plugin\IpReputation\AbuseIpDb
 */
final class AbuseIpDbPluginTest extends UnitTestCase {

  /**
   * Plugin definition array shared across tests.
   */
  private array $pluginDefinition = [
    'id' => 'abuseipdb',
    'label' => 'AbuseIPDB',
    'description' => 'AbuseIPDB v2 provider',
    'api_endpoint' => 'https://api.abuseipdb.com/api/v2/check',
  ];

  /**
   * Builds an AbuseIpDb plugin instance with provided mock collaborators.
   */
  private function buildPlugin(
    ?ClientInterface $httpClient = NULL,
    ?CacheBackendInterface $cache = NULL,
    array $providerConfig = [],
  ): AbuseIpDb {
    $defaultProviderConfig = array_merge([
      'api_key'     => 'test-api-key-12345',
      'api_key_id'  => '',
      'threshold'   => 85,
      'max_age_days'=> 30,
      'cache_ttl'   => 3600,
    ], $providerConfig);

    $config = $this->createMock(Config::class);
    $config->method('get')
      ->willReturnCallback(static function (string $key) use ($defaultProviderConfig) {
        if ($key === 'reputation_providers.abuseipdb') {
          return $defaultProviderConfig;
        }
        return NULL;
      });

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($config);

    $httpClient ??= $this->createMock(ClientInterface::class);
    $cache ??= $this->createMock(CacheBackendInterface::class);
    $logger = $this->createMock(LoggerInterface::class);

    return new AbuseIpDb(
      [],
      'abuseipdb',
      $this->pluginDefinition,
      $httpClient,
      $cache,
      $configFactory,
      $logger,
    );
  }

  /**
   * Builds a mock CacheBackendInterface that always returns a miss.
   */
  private function buildCacheMiss(): CacheBackendInterface {
    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn(FALSE);
    return $cache;
  }

  /**
   * Builds a successful AbuseIPDB-style Guzzle Response.
   */
  private function buildApiResponse(int $score, array $reports = []): Response {
    $body = json_encode([
      'data' => [
        'ipAddress'            => '1.2.3.4',
        'abuseConfidenceScore' => $score,
        'usageType'            => 'Data Center/Web Hosting/Transit',
        'isTor'                => FALSE,
        'reports'              => $reports,
      ],
    ]);
    return new Response(200, ['Content-Type' => 'application/json'], $body);
  }

  // -------------------------------------------------------------------------
  // isConfigured()
  // -------------------------------------------------------------------------

  /**
   * Tests that isConfigured() returns FALSE when api_key is empty.
   *
   * @covers ::isConfigured
   */
  public function testIsConfiguredReturnsFalseWhenApiKeyEmpty(): void {
    $plugin = $this->buildPlugin(providerConfig: ['api_key' => '', 'api_key_id' => '']);
    $this->assertFalse($plugin->isConfigured());
  }

  /**
   * Tests that isConfigured() returns TRUE when api_key is set.
   *
   * @covers ::isConfigured
   */
  public function testIsConfiguredReturnsTrueWhenApiKeySet(): void {
    $plugin = $this->buildPlugin();
    $this->assertTrue($plugin->isConfigured());
  }

  /**
   * Tests that checkIp() returns allowed result immediately when not configured.
   *
   * @covers ::checkIp
   */
  public function testCheckIpReturnsAllowedWhenNotConfigured(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->expects($this->never())->method('get');

    $plugin = $this->buildPlugin(
      httpClient: $httpClient,
      providerConfig: ['api_key' => '', 'api_key_id' => ''],
    );

    $result = $plugin->checkIp('1.2.3.4');

    $this->assertFalse($result->isBlocked);
    $this->assertFalse($result->providerError);
    $this->assertSame('abuseipdb', $result->providerName);
  }

  // -------------------------------------------------------------------------
  // Cache behavior
  // -------------------------------------------------------------------------

  /**
   * Tests that a cache hit for a non-blocked IP returns fromCache = true.
   *
   * @covers ::checkIp
   */
  public function testCacheHitForAllowedIpReturnsCachedResult(): void {
    $cacheItem = new \stdClass();
    $cacheItem->data = [
      'blocked'    => FALSE,
      'score'      => 20,
      'categories' => [],
      'timestamp'  => time() - 60,
    ];

    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn($cacheItem);

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->expects($this->never())->method('get');

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertFalse($result->isBlocked);
    $this->assertTrue($result->fromCache);
    $this->assertSame(20, $result->confidenceScore);
    $this->assertSame('abuseipdb', $result->providerName);
  }

  /**
   * Tests that a cache hit for a blocked IP returns isBlocked = true, fromCache = true.
   *
   * @covers ::checkIp
   */
  public function testCacheHitForBlockedIpReturnsCachedBlockedResult(): void {
    $cacheItem = new \stdClass();
    $cacheItem->data = [
      'blocked'    => TRUE,
      'score'      => 92,
      'categories' => [['category' => 18]],
      'timestamp'  => time() - 60,
    ];

    $cache = $this->createMock(CacheBackendInterface::class);
    $cache->method('get')->willReturn($cacheItem);

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->expects($this->never())->method('get');

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertTrue($result->isBlocked);
    $this->assertTrue($result->fromCache);
    $this->assertSame(92, $result->confidenceScore);
    $this->assertSame([['category' => 18]], $result->abuseCategories);
  }

  /**
   * Tests that a cache miss triggers an HTTP request.
   *
   * @covers ::checkIp
   */
  public function testCacheMissTriggersHttpRequest(): void {
    $cache = $this->buildCacheMiss();

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->expects($this->once())
      ->method('get')
      ->willReturn($this->buildApiResponse(30));

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $plugin->checkIp('1.2.3.4');
  }

  /**
   * Tests that the cache is written after a successful API call.
   *
   * @covers ::checkIp
   */
  public function testCacheWrittenAfterSuccessfulApiCall(): void {
    $cache = $this->buildCacheMiss();
    $cache->expects($this->once())
      ->method('set')
      ->with(
        $this->stringStartsWith('abuseipdb:'),
        $this->callback(static fn($data) => isset($data['blocked'], $data['score'], $data['timestamp'])),
        $this->greaterThan(time()),
      );

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->buildApiResponse(50));

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $plugin->checkIp('1.2.3.4');
  }

  /**
   * Tests that the cache is NOT written when cache_ttl is 0.
   *
   * @covers ::checkIp
   */
  public function testCacheNotWrittenWhenTtlIsZero(): void {
    $cache = $this->buildCacheMiss();
    $cache->expects($this->never())->method('set');

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->buildApiResponse(50));

    $plugin = $this->buildPlugin(
      httpClient: $httpClient,
      cache: $cache,
      providerConfig: ['api_key' => 'test-key', 'cache_ttl' => 0],
    );
    $plugin->checkIp('1.2.3.4');
  }

  // -------------------------------------------------------------------------
  // Score / threshold logic
  // -------------------------------------------------------------------------

  /**
   * Tests that a score at or above threshold returns isBlocked = true.
   *
   * @covers ::checkIp
   */
  public function testScoreAtThresholdReturnsBlocked(): void {
    $cache = $this->buildCacheMiss();
    $cache->method('set');

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->buildApiResponse(85)); // Exactly threshold.

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache); // threshold default 85
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertTrue($result->isBlocked);
    $this->assertSame(85, $result->confidenceScore);
    $this->assertFalse($result->fromCache);
  }

  /**
   * Tests that a score above threshold returns isBlocked = true.
   *
   * @covers ::checkIp
   */
  public function testScoreAboveThresholdReturnsBlocked(): void {
    $cache = $this->buildCacheMiss();
    $cache->method('set');

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->buildApiResponse(99));

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertTrue($result->isBlocked);
    $this->assertSame(99, $result->confidenceScore);
    $this->assertFalse($result->providerError);
  }

  /**
   * Tests that a score below threshold returns isBlocked = false.
   *
   * @covers ::checkIp
   */
  public function testScoreBelowThresholdReturnsAllowed(): void {
    $cache = $this->buildCacheMiss();
    $cache->method('set');

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->buildApiResponse(50));

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertFalse($result->isBlocked);
    $this->assertSame(50, $result->confidenceScore);
  }

  /**
   * Tests that a score of 0 (completely clean IP) is allowed.
   *
   * @covers ::checkIp
   */
  public function testZeroScoreIsAllowed(): void {
    $cache = $this->buildCacheMiss();
    $cache->method('set');

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->buildApiResponse(0));

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertFalse($result->isBlocked);
    $this->assertSame(0, $result->confidenceScore);
  }

  /**
   * Tests that categories (reports) are passed through to a blocked result.
   *
   * @covers ::checkIp
   */
  public function testReportsCategoriesPassedToBlockedResult(): void {
    $reports = [
      ['category' => 18, 'reportedAt' => '2024-01-01'],
      ['category' => 21, 'reportedAt' => '2024-01-02'],
    ];
    $cache = $this->buildCacheMiss();
    $cache->method('set');

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->buildApiResponse(90, $reports));

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertTrue($result->isBlocked);
    $this->assertSame($reports, $result->abuseCategories);
  }

  // -------------------------------------------------------------------------
  // Error / fail-open behavior
  // -------------------------------------------------------------------------

  /**
   * Tests that a GuzzleException (network error) returns a fail-open result.
   *
   * @covers ::checkIp
   */
  public function testConnectExceptionReturnsFailOpen(): void {
    $cache = $this->buildCacheMiss();
    $cache->expects($this->never())->method('set');

    $guzzleRequest = $this->createMock(GuzzleRequestInterface::class);
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')
      ->willThrowException(new ConnectException('Connection refused', $guzzleRequest));

    // Need to build with explicit logger to assert warning.
    $config = $this->createMock(Config::class);
    $config->method('get')->willReturn([
      'api_key'      => 'test-key',
      'api_key_id'   => '',
      'threshold'    => 85,
      'max_age_days' => 30,
      'cache_ttl'    => 3600,
    ]);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('warning');

    $plugin = new AbuseIpDb(
      [], 'abuseipdb', $this->pluginDefinition,
      $httpClient, $cache, $configFactory, $logger,
    );

    $result = $plugin->checkIp('1.2.3.4');

    $this->assertFalse($result->isBlocked);
    $this->assertTrue($result->providerError);
    $this->assertSame('abuseipdb', $result->providerName);
  }

  /**
   * Tests that a 401 HTTP response returns a fail-open result.
   *
   * @covers ::checkIp
   */
  public function testHttp401ResponseReturnsFailOpen(): void {
    $cache = $this->buildCacheMiss();
    $cache->expects($this->never())->method('set');

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn(new Response(401, [], '{"errors":[{"detail":"Invalid API key"}]}'));

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertFalse($result->isBlocked);
    $this->assertTrue($result->providerError);
  }

  /**
   * Tests that a 500 HTTP response returns a fail-open result.
   *
   * @covers ::checkIp
   */
  public function testHttp500ResponseReturnsFailOpen(): void {
    $cache = $this->buildCacheMiss();

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn(new Response(500, [], 'Internal Server Error'));

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertFalse($result->isBlocked);
    $this->assertTrue($result->providerError);
  }

  /**
   * Tests that an invalid (non-JSON) response body returns a fail-open result.
   *
   * @covers ::checkIp
   */
  public function testInvalidJsonResponseBodyReturnsFailOpen(): void {
    $cache = $this->buildCacheMiss();

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn(new Response(200, [], 'NOT JSON AT ALL'));

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertFalse($result->isBlocked);
    $this->assertTrue($result->providerError);
  }

  /**
   * Tests that a response missing the abuseConfidenceScore field returns fail-open.
   *
   * @covers ::checkIp
   */
  public function testMissingScoreFieldReturnsFailOpen(): void {
    $cache = $this->buildCacheMiss();

    $body = json_encode(['data' => ['ipAddress' => '1.2.3.4']]);
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn(new Response(200, [], $body));

    $plugin = $this->buildPlugin(httpClient: $httpClient, cache: $cache);
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertFalse($result->isBlocked);
    $this->assertTrue($result->providerError);
  }

  /**
   * Tests that a custom threshold of 50 is applied correctly.
   *
   * @covers ::checkIp
   */
  public function testCustomThresholdOfFiftyIsApplied(): void {
    $cache = $this->buildCacheMiss();
    $cache->method('set');

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->buildApiResponse(55));

    // threshold = 50: score 55 >= 50 => blocked.
    $plugin = $this->buildPlugin(
      httpClient: $httpClient,
      cache: $cache,
      providerConfig: ['api_key' => 'test-key', 'threshold' => 50],
    );
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertTrue($result->isBlocked);
    $this->assertSame(55, $result->confidenceScore);
  }

}
