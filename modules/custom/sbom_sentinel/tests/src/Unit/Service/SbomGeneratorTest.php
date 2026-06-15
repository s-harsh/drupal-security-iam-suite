<?php

declare(strict_types=1);

namespace Drupal\Tests\sbom_sentinel\Unit\Service;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\sbom_sentinel\Service\NisRiskScorer;
use Drupal\sbom_sentinel\Service\OsvApiClient;
use Drupal\sbom_sentinel\Service\SbomGenerator;
use Drupal\sbom_sentinel\Value\SbomComponent;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for SbomGenerator.
 *
 * @coversDefaultClass \Drupal\sbom_sentinel\Service\SbomGenerator
 * @group sbom_sentinel
 */
final class SbomGeneratorTest extends UnitTestCase {

  /**
   * Mock OSV API client.
   */
  private MockObject $osvApiClient;

  /**
   * NIS risk scorer (real instance — no external calls).
   */
  private NisRiskScorer $nisRiskScorer;

  /**
   * Mock config factory.
   */
  private MockObject $configFactory;

  /**
   * Mock cache backend.
   */
  private MockObject $cache;

  /**
   * Mock logger.
   */
  private MockObject $logger;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->osvApiClient = $this->createMock(OsvApiClient::class);
    $this->nisRiskScorer = new NisRiskScorer();
    $this->configFactory = $this->createMock(ConfigFactoryInterface::class);
    $this->cache = $this->createMock(CacheBackendInterface::class);
    $this->logger = $this->createMock(LoggerInterface::class);
  }

  /**
   * Builds an SbomGenerator with default mock config.
   *
   * @param string $composerLockPath
   *   Path returned by config for composer_lock_path.
   * @param int $cacheTtl
   *   Cache TTL returned by config.
   *
   * @return \Drupal\sbom_sentinel\Service\SbomGenerator
   */
  private function buildGenerator(
    string $composerLockPath = '/nonexistent/composer.lock',
    int $cacheTtl = 3600,
  ): SbomGenerator {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['composer_lock_path', $composerLockPath],
      ['scan_cache_ttl', $cacheTtl],
    ]);
    $this->configFactory->method('get')
      ->with('sbom_sentinel.settings')
      ->willReturn($config);

    return new SbomGenerator(
      $this->osvApiClient,
      $this->nisRiskScorer,
      $this->configFactory,
      $this->cache,
      $this->logger,
    );
  }

  // -------------------------------------------------------------------------
  // parseComposerLock()
  // -------------------------------------------------------------------------

  /**
   * @covers ::parseComposerLock
   */
  public function testParseComposerLockReturnsErrorWhenFileNotFound(): void {
    $generator = $this->buildGenerator();
    [$components, $errors] = $generator->parseComposerLock('/nonexistent/path/composer.lock');

    $this->assertSame([], $components);
    $this->assertNotEmpty($errors);
  }

  /**
   * @covers ::parseComposerLock
   */
  public function testParseComposerLockParsesPackagesFromRealComposerLock(): void {
    // Write a temporary composer.lock with one package.
    $lockData = json_encode([
      'packages' => [
        [
          'name' => 'drupal/core',
          'version' => '11.1.0',
          'type' => 'drupal-core',
          'description' => 'Drupal core',
          'license' => ['GPL-2.0-or-later'],
          'source' => ['url' => 'https://github.com/drupal/drupal'],
        ],
      ],
      'packages-dev' => [],
    ]);

    $tmpFile = sys_get_temp_dir() . '/sbom_sentinel_test_' . uniqid() . '.json';
    file_put_contents($tmpFile, $lockData);

    try {
      $generator = $this->buildGenerator($tmpFile);
      [$components, $errors] = $generator->parseComposerLock($tmpFile);
    }
    finally {
      unlink($tmpFile);
    }

    $this->assertSame([], $errors);
    $this->assertCount(1, $components);
    $this->assertInstanceOf(SbomComponent::class, $components[0]);
    $this->assertSame('drupal/core', $components[0]->name);
    $this->assertSame('11.1.0', $components[0]->version);
  }

  /**
   * @covers ::parseComposerLock
   */
  public function testParseComposerLockIncludesDevPackages(): void {
    $lockData = json_encode([
      'packages' => [
        ['name' => 'drupal/core', 'version' => '11.1.0', 'type' => 'drupal-core'],
      ],
      'packages-dev' => [
        ['name' => 'phpunit/phpunit', 'version' => '10.0.0', 'type' => 'library'],
      ],
    ]);

    $tmpFile = sys_get_temp_dir() . '/sbom_sentinel_test_' . uniqid() . '.json';
    file_put_contents($tmpFile, $lockData);

    try {
      $generator = $this->buildGenerator($tmpFile);
      [$components, $errors] = $generator->parseComposerLock($tmpFile);
    }
    finally {
      unlink($tmpFile);
    }

    $this->assertCount(2, $components);
    $names = array_map(fn($c) => $c->name, $components);
    $this->assertContains('drupal/core', $names);
    $this->assertContains('phpunit/phpunit', $names);
  }

  /**
   * @covers ::parseComposerLock
   */
  public function testParseComposerLockNormalisesVersionPrefix(): void {
    $lockData = json_encode([
      'packages' => [
        ['name' => 'drupal/core', 'version' => 'v11.1.0', 'type' => 'drupal-core'],
      ],
      'packages-dev' => [],
    ]);

    $tmpFile = sys_get_temp_dir() . '/sbom_sentinel_test_' . uniqid() . '.json';
    file_put_contents($tmpFile, $lockData);

    try {
      $generator = $this->buildGenerator($tmpFile);
      [$components] = $generator->parseComposerLock($tmpFile);
    }
    finally {
      unlink($tmpFile);
    }

    $this->assertSame('11.1.0', $components[0]->version);
  }

  /**
   * @covers ::parseComposerLock
   */
  public function testParseComposerLockSkipsPackagesWithMissingName(): void {
    $lockData = json_encode([
      'packages' => [
        ['version' => '1.0.0', 'type' => 'library'],
        ['name' => 'vendor/pkg', 'version' => '1.0.0', 'type' => 'library'],
      ],
      'packages-dev' => [],
    ]);

    $tmpFile = sys_get_temp_dir() . '/sbom_sentinel_test_' . uniqid() . '.json';
    file_put_contents($tmpFile, $lockData);

    try {
      $generator = $this->buildGenerator($tmpFile);
      [$components] = $generator->parseComposerLock($tmpFile);
    }
    finally {
      unlink($tmpFile);
    }

    $this->assertCount(1, $components);
    $this->assertSame('vendor/pkg', $components[0]->name);
  }

  /**
   * @covers ::parseComposerLock
   */
  public function testParseComposerLockBuildsCorrectPurl(): void {
    $lockData = json_encode([
      'packages' => [
        ['name' => 'drupal/views', 'version' => '11.0.0', 'type' => 'drupal-module'],
      ],
      'packages-dev' => [],
    ]);

    $tmpFile = sys_get_temp_dir() . '/sbom_sentinel_test_' . uniqid() . '.json';
    file_put_contents($tmpFile, $lockData);

    try {
      $generator = $this->buildGenerator($tmpFile);
      [$components] = $generator->parseComposerLock($tmpFile);
    }
    finally {
      unlink($tmpFile);
    }

    $this->assertSame('pkg:composer/drupal/views@11.0.0', $components[0]->purl);
  }

  // -------------------------------------------------------------------------
  // buildCycloneDxDocument()
  // -------------------------------------------------------------------------

  /**
   * @covers ::buildCycloneDxDocument
   */
  public function testBuildCycloneDxDocumentReturnsCycloneDxBomFormat(): void {
    $generator = $this->buildGenerator();
    $doc = $generator->buildCycloneDxDocument([], []);

    $this->assertSame('CycloneDX', $doc['bomFormat']);
  }

  /**
   * @covers ::buildCycloneDxDocument
   */
  public function testBuildCycloneDxDocumentReturnsSpecVersion16(): void {
    $generator = $this->buildGenerator();
    $doc = $generator->buildCycloneDxDocument([], []);

    $this->assertSame('1.6', $doc['specVersion']);
  }

  /**
   * @covers ::buildCycloneDxDocument
   */
  public function testBuildCycloneDxDocumentHasSerialNumber(): void {
    $generator = $this->buildGenerator();
    $doc = $generator->buildCycloneDxDocument([], []);

    $this->assertArrayHasKey('serialNumber', $doc);
    $this->assertStringStartsWith('urn:uuid:', $doc['serialNumber']);
  }

  /**
   * @covers ::buildCycloneDxDocument
   */
  public function testBuildCycloneDxDocumentHasMetadataTimestamp(): void {
    $generator = $this->buildGenerator();
    $doc = $generator->buildCycloneDxDocument([], []);

    $this->assertArrayHasKey('metadata', $doc);
    $this->assertArrayHasKey('timestamp', $doc['metadata']);
    $this->assertNotEmpty($doc['metadata']['timestamp']);
  }

  /**
   * @covers ::buildCycloneDxDocument
   */
  public function testBuildCycloneDxDocumentIncludesToolEntry(): void {
    $generator = $this->buildGenerator();
    $doc = $generator->buildCycloneDxDocument([], []);

    $this->assertNotEmpty($doc['metadata']['tools']);
    $tool = $doc['metadata']['tools'][0];
    $this->assertSame('sbom_sentinel', $tool['name']);
  }

  /**
   * @covers ::buildCycloneDxDocument
   */
  public function testBuildCycloneDxDocumentMapsComponentsToCdxComponents(): void {
    $component = new SbomComponent(
      name: 'drupal/core',
      version: '11.1.0',
      type: 'drupal-core',
      description: 'Drupal core',
      purl: 'pkg:composer/drupal/core@11.1.0',
      bomRef: 'abc123',
      licenses: ['GPL-2.0-or-later'],
      sourceUrl: '',
    );
    $generator = $this->buildGenerator();
    $doc = $generator->buildCycloneDxDocument([$component], []);

    $this->assertCount(1, $doc['components']);
    $cdxComp = $doc['components'][0];
    $this->assertSame('drupal/core', $cdxComp['name']);
    $this->assertSame('11.1.0', $cdxComp['version']);
    $this->assertSame('pkg:composer/drupal/core@11.1.0', $cdxComp['purl']);
  }

  // -------------------------------------------------------------------------
  // getCachedResults() and invalidateCache()
  // -------------------------------------------------------------------------

  /**
   * @covers ::getCachedResults
   */
  public function testGetCachedResultsReturnsNullWhenNoCacheEntry(): void {
    $this->cache->method('get')->willReturn(FALSE);
    $generator = $this->buildGenerator();

    $this->assertNull($generator->getCachedResults());
  }

  /**
   * @covers ::getCachedResults
   */
  public function testGetCachedResultsReturnsCachedData(): void {
    $cachedEntry = new \stdClass();
    $cachedEntry->data = ['component_count' => 5, 'results' => [], 'sbom' => [], 'scanned_at' => time(), 'errors' => []];

    $this->cache->method('get')->willReturn($cachedEntry);
    $generator = $this->buildGenerator();

    $result = $generator->getCachedResults();
    $this->assertSame(5, $result['component_count']);
  }

  /**
   * @covers ::invalidateCache
   */
  public function testInvalidateCacheCallsCacheDelete(): void {
    $this->cache->expects($this->once())
      ->method('delete')
      ->with('sbom_sentinel.scan_results');

    $generator = $this->buildGenerator();
    $generator->invalidateCache();
  }

  // -------------------------------------------------------------------------
  // scan() — uses cache
  // -------------------------------------------------------------------------

  /**
   * @covers ::scan
   */
  public function testScanReturnsCachedDataWhenAvailable(): void {
    $cachedEntry = new \stdClass();
    $cachedEntry->data = [
      'component_count' => 42,
      'results' => [],
      'sbom' => ['bomFormat' => 'CycloneDX'],
      'scanned_at' => time(),
      'errors' => [],
    ];
    $this->cache->method('get')->willReturn($cachedEntry);

    $generator = $this->buildGenerator();
    $result = $generator->scan(bypassCache: FALSE);

    $this->assertSame(42, $result['component_count']);
  }

  /**
   * @covers ::scan
   */
  public function testScanReturnsOutputWithRequiredKeys(): void {
    // Bypass cache, use nonexistent path so parseComposerLock returns error.
    $this->cache->method('get')->willReturn(FALSE);
    $this->cache->method('set');

    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['composer_lock_path', '/nonexistent/path/composer.lock'],
      ['scan_cache_ttl', 0],
    ]);
    $this->configFactory->method('get')->willReturn($config);

    $generator = new SbomGenerator(
      $this->osvApiClient,
      $this->nisRiskScorer,
      $this->configFactory,
      $this->cache,
      $this->logger,
    );

    $result = $generator->scan(bypassCache: TRUE);

    $this->assertArrayHasKey('sbom', $result);
    $this->assertArrayHasKey('results', $result);
    $this->assertArrayHasKey('component_count', $result);
    $this->assertArrayHasKey('scanned_at', $result);
    $this->assertArrayHasKey('errors', $result);
  }

}
