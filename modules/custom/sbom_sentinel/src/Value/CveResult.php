<?php

declare(strict_types=1);

namespace Drupal\sbom_sentinel\Value;

/**
 * Immutable value object representing the OSV.dev vulnerability query result
 * for a single SBOM component.
 *
 * Aggregates the raw OSV vulnerability list and the computed NIS2 risk level
 * for display in the admin report and export files.
 */
final readonly class CveResult {

  /**
   * Constructs a CveResult.
   *
   * @param string $packageName
   *   The Composer package name this result belongs to (e.g. "drupal/core").
   * @param string $packageVersion
   *   The installed version that was checked.
   * @param bool $apiError
   *   TRUE when the OSV.dev API could not be reached or returned an error.
   * @param string $errorMessage
   *   A short description of the error. Never contains sensitive data.
   * @param array<int, array<string, mixed>> $vulnerabilities
   *   Raw OSV vulnerability objects as associative arrays. Each element has at
   *   least 'id' and 'summary' keys. CVSS severity is nested under 'severity'.
   * @param string $nisRiskLevel
   *   The computed NIS2 risk level: 'critical', 'high', 'medium', 'low',
   *   or 'none' when no CVEs were found.
   * @param float $maxCvssScore
   *   The highest CVSS v3 base score across all vulnerabilities, or 0.0 when
   *   no scored vulnerabilities were found.
   */
  public function __construct(
    public readonly string $packageName,
    public readonly string $packageVersion,
    public readonly bool $apiError,
    public readonly string $errorMessage,
    public readonly array $vulnerabilities,
    public readonly string $nisRiskLevel,
    public readonly float $maxCvssScore,
  ) {}

  /**
   * Returns the number of vulnerabilities found.
   *
   * @return int
   *   Count of CVE/OSV vulnerability records.
   */
  public function cveCount(): int {
    return count($this->vulnerabilities);
  }

  /**
   * Returns TRUE when at least one vulnerability was found and no API error.
   *
   * @return bool
   *   Whether the component has known vulnerabilities.
   */
  public function hasVulnerabilities(): bool {
    return !$this->apiError && $this->cveCount() > 0;
  }

  /**
   * Returns the OSV vulnerability IDs for display and linking.
   *
   * @return array<string>
   *   Array of OSV ID strings (e.g. "GHSA-xxxx-xxxx-xxxx", "CVE-2024-1234").
   */
  public function osvIds(): array {
    $ids = [];
    foreach ($this->vulnerabilities as $vuln) {
      if (!empty($vuln['id'])) {
        $ids[] = (string) $vuln['id'];
      }
    }
    return $ids;
  }

}
