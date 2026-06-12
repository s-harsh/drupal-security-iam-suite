<?php

declare(strict_types=1);

namespace Drupal\sbom_sentinel\Service;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\sbom_sentinel\Value\CveResult;
use Drupal\sbom_sentinel\Value\SbomComponent;
use Psr\Log\LoggerInterface;

/**
 * Generates CycloneDX 1.6 SBOMs and drives the OSV.dev vulnerability scan.
 *
 * Reads composer.lock from the configured path, maps each package to an
 * SbomComponent value object, queries OSV.dev via OsvApiClient, scores each
 * component with NisRiskScorer, and caches the results. The final SBOM
 * document is returned as an associative array that can be JSON-encoded or
 * converted to XML by the export controllers.
 */
final class SbomGenerator {

  /**
   * The cache key prefix for scan results.
   */
  private const CACHE_KEY = 'sbom_sentinel.scan_results';

  /**
   * The module settings config object name.
   */
  private const CONFIG_NAME = 'sbom_sentinel.settings';

  /**
   * Constructs an SbomGenerator.
   *
   * @param \Drupal\sbom_sentinel\Service\OsvApiClient $osvApiClient
   *   The OSV.dev API client.
   * @param \Drupal\sbom_sentinel\Service\NisRiskScorer $nisRiskScorer
   *   The NIS2 risk scorer.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache
   *   The module cache bin.
   * @param \Psr\Log\LoggerInterface $logger
   *   The module logger channel.
   */
  public function __construct(
    private readonly OsvApiClient $osvApiClient,
    private readonly NisRiskScorer $nisRiskScorer,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly CacheBackendInterface $cache,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Runs the full SBOM scan pipeline.
   *
   * 1. Reads and parses composer.lock.
   * 2. Builds SbomComponent value objects.
   * 3. Queries OSV.dev for each component (respecting cache).
   * 4. Scores each result with NisRiskScorer.
   * 5. Returns the complete CycloneDX document array + scan metadata.
   *
   * @param bool $bypassCache
   *   When TRUE the cached results are ignored and a fresh scan is performed.
   *
   * @return array{
   *   sbom: array<string, mixed>,
   *   results: array<string, \Drupal\sbom_sentinel\Value\CveResult>,
   *   component_count: int,
   *   scanned_at: int,
   *   errors: array<string>,
   * }
   *   The scan output keyed by the above keys.
   */
  public function scan(bool $bypassCache = FALSE): array {
    if (!$bypassCache) {
      $cached = $this->cache->get(self::CACHE_KEY);
      if ($cached !== FALSE) {
        return $cached->data;
      }
    }

    $config = $this->configFactory->get(self::CONFIG_NAME);
    $composerLockPath = (string) $config->get('composer_lock_path');
    $cacheTtl = (int) $config->get('scan_cache_ttl');

    [$components, $parseErrors] = $this->parseComposerLock($composerLockPath);

    $results = [];
    foreach ($components as $component) {
      $results[$component->name] = $this->scanComponent($component);
    }

    $sbom = $this->buildCycloneDxDocument($components, $results);

    $output = [
      'sbom' => $sbom,
      'results' => $results,
      'component_count' => count($components),
      'scanned_at' => time(),
      'errors' => $parseErrors,
    ];

    if ($cacheTtl > 0) {
      $this->cache->set(self::CACHE_KEY, $output, time() + $cacheTtl);
    }

    return $output;
  }

  /**
   * Returns only the cached scan results without re-running the scan.
   *
   * Returns NULL when no cached results exist.
   *
   * @return array<string, mixed>|null
   *   Cached scan output or NULL.
   */
  public function getCachedResults(): ?array {
    $cached = $this->cache->get(self::CACHE_KEY);
    return $cached !== FALSE ? $cached->data : NULL;
  }

  /**
   * Invalidates the scan result cache, forcing a fresh scan on the next call.
   */
  public function invalidateCache(): void {
    $this->cache->delete(self::CACHE_KEY);
  }

  /**
   * Parses composer.lock and returns a list of SbomComponent value objects.
   *
   * @param string $composerLockPath
   *   Absolute or Drupal-root-relative path to composer.lock.
   *
   * @return array{0: array<int, \Drupal\sbom_sentinel\Value\SbomComponent>, 1: array<string>}
   *   Tuple of [components[], errors[]].
   */
  public function parseComposerLock(string $composerLockPath): array {
    // Resolve to absolute path relative to the Drupal root.
    if (!str_starts_with($composerLockPath, '/') && !preg_match('/^[A-Z]:\\\\/i', $composerLockPath)) {
      $root = DRUPAL_ROOT ?? dirname(__DIR__, 6);
      $composerLockPath = $root . '/' . ltrim($composerLockPath, '/\\');
    }

    if (!file_exists($composerLockPath) || !is_readable($composerLockPath)) {
      $this->logger->warning(
        'SBOM Sentinel: composer.lock not found or not readable at @path',
        ['@path' => $composerLockPath],
      );
      return [[], ['composer.lock not found at: ' . $composerLockPath]];
    }

    $raw = file_get_contents($composerLockPath);
    if ($raw === FALSE) {
      return [[], ['Failed to read composer.lock']];
    }

    $data = json_decode($raw, associative: true);
    if (!is_array($data)) {
      return [[], ['Failed to parse composer.lock as JSON']];
    }

    $packages = array_merge(
      $data['packages'] ?? [],
      $data['packages-dev'] ?? [],
    );

    $components = [];
    foreach ($packages as $pkg) {
      if (!is_array($pkg)) {
        continue;
      }
      $component = $this->packageToComponent($pkg);
      if ($component !== NULL) {
        $components[] = $component;
      }
    }

    return [$components, []];
  }

  /**
   * Converts a raw composer.lock package entry to an SbomComponent.
   *
   * @param array<string, mixed> $pkg
   *   Raw package data from composer.lock.
   *
   * @return \Drupal\sbom_sentinel\Value\SbomComponent|null
   *   The component, or NULL when required fields are missing.
   */
  private function packageToComponent(array $pkg): ?SbomComponent {
    $name = (string) ($pkg['name'] ?? '');
    $version = (string) ($pkg['version'] ?? '');

    if ($name === '' || $version === '') {
      return NULL;
    }

    // Normalise version: strip leading "v" prefix.
    $version = ltrim($version, 'v');

    $type = (string) ($pkg['type'] ?? 'library');
    $description = (string) ($pkg['description'] ?? '');

    $purl = 'pkg:composer/' . $name . '@' . $version;
    $bomRef = md5($name . '@' . $version);

    $licenses = [];
    $licenseData = $pkg['license'] ?? [];
    if (is_array($licenseData)) {
      foreach ($licenseData as $lic) {
        if (is_string($lic) && $lic !== '') {
          $licenses[] = $lic;
        }
      }
    }
    elseif (is_string($licenseData) && $licenseData !== '') {
      $licenses[] = $licenseData;
    }

    $sourceUrl = '';
    $source = $pkg['source'] ?? [];
    if (is_array($source) && !empty($source['url'])) {
      $sourceUrl = (string) $source['url'];
    }

    return new SbomComponent(
      name: $name,
      version: $version,
      type: $type,
      description: $description,
      purl: $purl,
      bomRef: $bomRef,
      licenses: $licenses,
      sourceUrl: $sourceUrl,
    );
  }

  /**
   * Scans a single component against OSV.dev and scores the result.
   *
   * @param \Drupal\sbom_sentinel\Value\SbomComponent $component
   *   The component to scan.
   *
   * @return \Drupal\sbom_sentinel\Value\CveResult
   *   The scored vulnerability result.
   */
  private function scanComponent(SbomComponent $component): CveResult {
    $apiResult = $this->osvApiClient->queryComponent($component);

    if (!$apiResult['success']) {
      return new CveResult(
        packageName: $component->name,
        packageVersion: $component->version,
        apiError: TRUE,
        errorMessage: $apiResult['error_message'],
        vulnerabilities: [],
        nisRiskLevel: NisRiskScorer::LEVEL_NONE,
        maxCvssScore: 0.0,
      );
    }

    $vulns = $apiResult['vulnerabilities'];
    $riskLevel = $this->nisRiskScorer->computeRiskLevel($vulns);
    $maxScore = $this->nisRiskScorer->maxCvssScore($vulns);

    return new CveResult(
      packageName: $component->name,
      packageVersion: $component->version,
      apiError: FALSE,
      errorMessage: '',
      vulnerabilities: $vulns,
      nisRiskLevel: $riskLevel,
      maxCvssScore: $maxScore,
    );
  }

  /**
   * Builds a CycloneDX 1.6 SBOM document as an associative array.
   *
   * The array is ready for json_encode() or XML serialisation.
   *
   * @param array<int, \Drupal\sbom_sentinel\Value\SbomComponent> $components
   *   The full list of SBOM components.
   * @param array<string, \Drupal\sbom_sentinel\Value\CveResult> $results
   *   Vulnerability scan results keyed by package name.
   *
   * @return array<string, mixed>
   *   The CycloneDX 1.6 document.
   */
  public function buildCycloneDxDocument(array $components, array $results): array {
    $cdxComponents = [];
    foreach ($components as $component) {
      $result = $results[$component->name] ?? NULL;
      $cdxComponents[] = $this->buildCdxComponent($component, $result);
    }

    return [
      'bomFormat' => 'CycloneDX',
      'specVersion' => '1.6',
      'serialNumber' => 'urn:uuid:' . $this->generateUuid(),
      'version' => 1,
      'metadata' => [
        'timestamp' => date('c'),
        'tools' => [
          [
            'vendor' => 'SBOM Sentinel',
            'name' => 'sbom_sentinel',
            'version' => '1.0.0',
          ],
        ],
        'component' => [
          'type' => 'application',
          'name' => 'Drupal',
          'bom-ref' => 'drupal-application',
        ],
      ],
      'components' => $cdxComponents,
      'vulnerabilities' => $this->buildCdxVulnerabilities($results),
    ];
  }

  /**
   * Builds a CycloneDX component element from an SbomComponent and CveResult.
   *
   * @param \Drupal\sbom_sentinel\Value\SbomComponent $component
   *   The SBOM component.
   * @param \Drupal\sbom_sentinel\Value\CveResult|null $result
   *   The vulnerability scan result, or NULL if not yet scanned.
   *
   * @return array<string, mixed>
   *   A CycloneDX component object.
   */
  private function buildCdxComponent(SbomComponent $component, ?CveResult $result): array {
    $cdxComponent = [
      'type' => 'library',
      'bom-ref' => $component->bomRef,
      'name' => $component->name,
      'version' => $component->version,
      'description' => $component->description,
      'purl' => $component->purl,
    ];

    if (!empty($component->licenses)) {
      $cdxComponent['licenses'] = array_map(
        fn(string $spdx) => ['license' => ['id' => $spdx]],
        $component->licenses,
      );
    }

    if ($component->sourceUrl !== '') {
      $cdxComponent['externalReferences'] = [
        [
          'type' => 'vcs',
          'url' => $component->sourceUrl,
        ],
      ];
    }

    if ($result !== NULL && !$result->apiError) {
      $cdxComponent['properties'] = [
        [
          'name' => 'sbom_sentinel:nis2_risk_level',
          'value' => $result->nisRiskLevel,
        ],
        [
          'name' => 'sbom_sentinel:cve_count',
          'value' => (string) $result->cveCount(),
        ],
        [
          'name' => 'sbom_sentinel:max_cvss_score',
          'value' => (string) $result->maxCvssScore,
        ],
      ];
    }

    return $cdxComponent;
  }

  /**
   * Builds the top-level CycloneDX vulnerabilities array.
   *
   * @param array<string, \Drupal\sbom_sentinel\Value\CveResult> $results
   *   Scan results keyed by package name.
   *
   * @return array<int, array<string, mixed>>
   *   The CycloneDX vulnerabilities array.
   */
  private function buildCdxVulnerabilities(array $results): array {
    $cdxVulns = [];
    foreach ($results as $result) {
      if (!$result->hasVulnerabilities()) {
        continue;
      }
      foreach ($result->vulnerabilities as $vuln) {
        $osvId = (string) ($vuln['id'] ?? '');
        if ($osvId === '') {
          continue;
        }
        $cdxVulns[] = [
          'id' => $osvId,
          'source' => [
            'name' => 'OSV',
            'url' => 'https://osv.dev/vulnerability/' . $osvId,
          ],
          'description' => (string) ($vuln['summary'] ?? ''),
          'affects' => [
            [
              'ref' => md5($result->packageName . '@' . $result->packageVersion),
            ],
          ],
          'ratings' => $this->buildCdxRatings($vuln),
        ];
      }
    }
    return $cdxVulns;
  }

  /**
   * Builds CycloneDX CVSS rating elements from an OSV vulnerability.
   *
   * @param array<string, mixed> $vuln
   *   An OSV vulnerability record.
   *
   * @return array<int, array<string, mixed>>
   *   CycloneDX rating objects.
   */
  private function buildCdxRatings(array $vuln): array {
    $ratings = [];
    $severities = $vuln['severity'] ?? [];
    if (!is_array($severities)) {
      return $ratings;
    }

    foreach ($severities as $sev) {
      if (!is_array($sev)) {
        continue;
      }
      $type = (string) ($sev['type'] ?? '');
      $score = (string) ($sev['score'] ?? '');
      if ($type !== '' && $score !== '') {
        $ratings[] = [
          'method' => match ($type) {
            'CVSS_V2' => 'CVSSv2',
            'CVSS_V3' => 'CVSSv3',
            'CVSS_V4' => 'CVSSv4',
            default => $type,
          },
          'vector' => $score,
        ];
      }
    }
    return $ratings;
  }

  /**
   * Generates a random UUID v4.
   *
   * @return string
   *   A UUID v4 string in the standard 8-4-4-4-12 format.
   */
  private function generateUuid(): string {
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
  }

}
