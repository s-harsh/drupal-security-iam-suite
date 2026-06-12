<?php

declare(strict_types=1);

namespace Drupal\sbom_sentinel\Drush\Commands;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\sbom_sentinel\Service\NisRiskScorer;
use Drupal\sbom_sentinel\Service\SbomGenerator;
use Drupal\sbom_sentinel\Value\CveResult;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;

/**
 * Drush 12 commands for SBOM Sentinel supply chain security scanning.
 *
 * Provides two commands:
 *   drush sbom:generate — generates the CycloneDX SBOM and outputs a summary.
 *   drush sbom:audit    — runs the full OSV.dev scan and reports CVE findings.
 *
 * Discovery: Drush 12 auto-discovers commandfiles in src/Drush/Commands/
 * when AutowireTrait is used.
 */
final class SbomSentinelCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * Constructs an SbomSentinelCommands instance.
   *
   * @param \Drupal\sbom_sentinel\Service\SbomGenerator $sbomGenerator
   *   The SBOM generator service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   */
  public function __construct(
    private readonly SbomGenerator $sbomGenerator,
    private readonly ConfigFactoryInterface $configFactory,
  ) {
    parent::__construct();
  }

  /**
   * Generates a CycloneDX 1.6 SBOM from composer.lock and outputs a summary.
   *
   * Reads composer.lock from the configured path, builds the SBOM document,
   * and prints the component count, format, and spec version. Optionally
   * writes the SBOM JSON to a file. Does NOT query OSV.dev for CVEs; use
   * sbom:audit for the full vulnerability scan.
   *
   * @param array<string, mixed> $options
   *   Drush options.
   */
  #[CLI\Command(name: 'sbom:generate', aliases: ['sbom-gen'])]
  #[CLI\Option(name: 'output', description: 'Write the CycloneDX JSON SBOM to the specified file path.')]
  #[CLI\Option(name: 'no-cache', description: 'Bypass the scan cache and force a fresh generation.')]
  #[CLI\Usage(name: 'drush sbom:generate', description: 'Generate SBOM and print summary.')]
  #[CLI\Usage(name: 'drush sbom:generate --output=/tmp/sbom.json', description: 'Generate SBOM and write JSON to a file.')]
  public function generate(array $options = ['output' => NULL, 'no-cache' => FALSE]): void {
    $bypassCache = (bool) ($options['no-cache'] ?? FALSE);
    $outputPath = $options['output'] ?? NULL;

    $this->io()->section('SBOM Sentinel — CycloneDX 1.6 SBOM Generation');

    try {
      $scanData = $this->sbomGenerator->scan(bypassCache: $bypassCache);
    }
    catch (\Throwable $e) {
      $this->io()->error('SBOM generation failed: ' . $e->getMessage());
      return;
    }

    $sbom = $scanData['sbom'] ?? [];
    $componentCount = (int) ($scanData['component_count'] ?? 0);
    $errors = $scanData['errors'] ?? [];

    $this->io()->listing([
      'Format: ' . ($sbom['bomFormat'] ?? 'CycloneDX'),
      'Spec version: ' . ($sbom['specVersion'] ?? 'unknown'),
      'Serial number: ' . ($sbom['serialNumber'] ?? 'unknown'),
      'Components: ' . $componentCount,
      'Generated at: ' . date('Y-m-d H:i:s', (int) ($scanData['scanned_at'] ?? time())),
    ]);

    if (!empty($errors)) {
      foreach ($errors as $err) {
        $this->io()->warning($err);
      }
    }

    if ($outputPath !== NULL) {
      $json = json_encode($sbom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
      if (file_put_contents($outputPath, $json ?: '{}') === FALSE) {
        $this->io()->error(sprintf('Failed to write SBOM JSON to %s', $outputPath));
        return;
      }
      $this->io()->success(sprintf('CycloneDX JSON SBOM written to %s', $outputPath));
    }
    else {
      $this->io()->success(sprintf('SBOM generated with %d components.', $componentCount));
    }
  }

  /**
   * Runs the full OSV.dev vulnerability audit and reports CVE findings.
   *
   * Scans all components from composer.lock against OSV.dev, computes NIS2
   * risk levels, and prints a summary table of vulnerable packages. Exits
   * with a non-zero code when critical or high vulnerabilities are found
   * (suitable for CI/CD pipeline enforcement).
   *
   * @param array<string, mixed> $options
   *   Drush options.
   */
  #[CLI\Command(name: 'sbom:audit', aliases: ['sbom-audit'])]
  #[CLI\Option(name: 'no-cache', description: 'Bypass the scan cache and force fresh OSV.dev API calls.')]
  #[CLI\Option(name: 'min-severity', description: 'Minimum NIS2 severity to report: critical, high, medium, low (default: low).')]
  #[CLI\Option(name: 'fail-on', description: 'Exit non-zero when vulnerabilities at or above this level exist: critical, high, medium, low (default: high).')]
  #[CLI\Usage(name: 'drush sbom:audit', description: 'Audit all components and report findings.')]
  #[CLI\Usage(name: 'drush sbom:audit --no-cache --fail-on=critical', description: 'Fresh scan, only fail CI on critical findings.')]
  #[CLI\Usage(name: 'drush sbom:audit --min-severity=high', description: 'Report only high and critical vulnerabilities.')]
  public function audit(
    array $options = [
      'no-cache' => FALSE,
      'min-severity' => 'low',
      'fail-on' => 'high',
    ],
  ): void {
    $bypassCache = (bool) ($options['no-cache'] ?? FALSE);
    $minSeverity = (string) ($options['min-severity'] ?? 'low');
    $failOn = (string) ($options['fail-on'] ?? 'high');

    $levelOrder = [
      NisRiskScorer::LEVEL_NONE => 0,
      NisRiskScorer::LEVEL_LOW => 1,
      NisRiskScorer::LEVEL_MEDIUM => 2,
      NisRiskScorer::LEVEL_HIGH => 3,
      NisRiskScorer::LEVEL_CRITICAL => 4,
    ];

    $this->io()->section('SBOM Sentinel — NIS2 Supply Chain Vulnerability Audit');

    try {
      $scanData = $this->sbomGenerator->scan(bypassCache: $bypassCache);
    }
    catch (\Throwable $e) {
      $this->io()->error('SBOM audit scan failed: ' . $e->getMessage());
      return;
    }

    /** @var array<string, CveResult> $results */
    $results = $scanData['results'] ?? [];
    $componentCount = (int) ($scanData['component_count'] ?? 0);
    $scannedAt = date('Y-m-d H:i:s', (int) ($scanData['scanned_at'] ?? time()));
    $errors = $scanData['errors'] ?? [];

    if (!empty($errors)) {
      foreach ($errors as $err) {
        $this->io()->warning($err);
      }
    }

    $this->io()->text(sprintf(
      'Scanned %d components at %s.',
      $componentCount,
      $scannedAt,
    ));

    // Filter and sort results.
    $minOrder = $levelOrder[$minSeverity] ?? 1;
    $findings = array_filter(
      $results,
      fn(CveResult $r) => $r->hasVulnerabilities()
        && ($levelOrder[$r->nisRiskLevel] ?? 0) >= $minOrder,
    );

    usort($findings, fn(CveResult $a, CveResult $b) =>
      ($levelOrder[$b->nisRiskLevel] ?? 0) <=> ($levelOrder[$a->nisRiskLevel] ?? 0)
    );

    if (empty($findings)) {
      $this->io()->success(sprintf(
        'No vulnerabilities found at or above "%s" severity across %d components.',
        $minSeverity,
        $componentCount,
      ));
      return;
    }

    // Print findings table.
    $headers = ['Package', 'Version', 'NIS2 Risk', 'CVE Count', 'Max CVSS', 'OSV IDs'];
    $tableRows = [];
    foreach ($findings as $result) {
      $osvIds = implode(', ', array_slice($result->osvIds(), 0, 3));
      if (count($result->osvIds()) > 3) {
        $osvIds .= ' (+' . (count($result->osvIds()) - 3) . ' more)';
      }
      $tableRows[] = [
        $result->packageName,
        $result->packageVersion,
        strtoupper($result->nisRiskLevel),
        (string) $result->cveCount(),
        $result->maxCvssScore > 0 ? number_format($result->maxCvssScore, 1) : 'N/A',
        $osvIds ?: '—',
      ];
    }

    $this->io()->table($headers, $tableRows);

    $vulnerableCount = count($findings);
    $this->io()->warning(sprintf(
      '%d component(s) have known vulnerabilities at or above "%s" severity.',
      $vulnerableCount,
      $minSeverity,
    ));

    // Determine if we should exit non-zero.
    $failOnOrder = $levelOrder[$failOn] ?? 3;
    $shouldFail = FALSE;
    foreach ($findings as $result) {
      if (($levelOrder[$result->nisRiskLevel] ?? 0) >= $failOnOrder) {
        $shouldFail = TRUE;
        break;
      }
    }

    if ($shouldFail) {
      $this->io()->error(sprintf(
        'Audit FAILED: vulnerabilities at or above "%s" severity were found.',
        $failOn,
      ));
      throw new \RuntimeException(sprintf(
        'SBOM audit found vulnerabilities at or above "%s" severity.',
        $failOn,
      ));
    }
  }

}
