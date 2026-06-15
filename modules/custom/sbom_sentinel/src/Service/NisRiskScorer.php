<?php

declare(strict_types=1);

namespace Drupal\sbom_sentinel\Service;

/**
 * Computes NIS2 Article 21 risk levels from OSV.dev vulnerability data.
 *
 * Maps CVSS v3 base scores and OSV severity ratings to the four NIS2 risk
 * bands used in SBOM Sentinel reports:
 *   critical — CVSS >= 9.0 or OSV CRITICAL
 *   high     — CVSS 7.0–8.9 or OSV HIGH
 *   medium   — CVSS 4.0–6.9 or OSV MODERATE/MEDIUM
 *   low      — CVSS < 4.0 or OSV LOW
 *   none     — no vulnerabilities found
 */
final class NisRiskScorer {

  /**
   * NIS2 risk level for CVSS critical (>= 9.0).
   */
  public const LEVEL_CRITICAL = 'critical';

  /**
   * NIS2 risk level for CVSS high (7.0–8.9).
   */
  public const LEVEL_HIGH = 'high';

  /**
   * NIS2 risk level for CVSS medium (4.0–6.9).
   */
  public const LEVEL_MEDIUM = 'medium';

  /**
   * NIS2 risk level for CVSS low (< 4.0).
   */
  public const LEVEL_LOW = 'low';

  /**
   * NIS2 risk level when no vulnerabilities exist.
   */
  public const LEVEL_NONE = 'none';

  /**
   * Computes the NIS2 risk level from a list of OSV vulnerability records.
   *
   * Iterates over all severity ratings in the vulnerability list and returns
   * the worst (highest) NIS2 band found. Falls back to CVSS score parsing
   * when OSV severity strings are absent.
   *
   * @param array<int, array<string, mixed>> $vulnerabilities
   *   Raw OSV vulnerability objects. Each may contain a 'severity' key with
   *   an array of objects with 'type' and 'score' fields, or a top-level
   *   CVSS score string.
   *
   * @return string
   *   One of: 'critical', 'high', 'medium', 'low', 'none'.
   */
  public function computeRiskLevel(array $vulnerabilities): string {
    if (empty($vulnerabilities)) {
      return self::LEVEL_NONE;
    }

    $worst = self::LEVEL_LOW;

    foreach ($vulnerabilities as $vuln) {
      $level = $this->riskLevelFromVuln($vuln);
      $worst = $this->maxLevel($worst, $level);

      // Early exit: cannot get worse than critical.
      if ($worst === self::LEVEL_CRITICAL) {
        return self::LEVEL_CRITICAL;
      }
    }

    return $worst;
  }

  /**
   * Extracts the maximum CVSS v3 base score from a list of vulnerabilities.
   *
   * @param array<int, array<string, mixed>> $vulnerabilities
   *   Raw OSV vulnerability objects.
   *
   * @return float
   *   The highest CVSS v3 base score found, or 0.0 if none is present.
   */
  public function maxCvssScore(array $vulnerabilities): float {
    $max = 0.0;

    foreach ($vulnerabilities as $vuln) {
      $score = $this->extractCvssScore($vuln);
      if ($score > $max) {
        $max = $score;
      }
    }

    return $max;
  }

  /**
   * Maps a CVSS v3 score to a NIS2 risk level string.
   *
   * @param float $score
   *   A CVSS v3 base score in the range 0.0–10.0.
   *
   * @return string
   *   One of: 'critical', 'high', 'medium', 'low', 'none'.
   */
  public function levelFromCvssScore(float $score): string {
    if ($score <= 0.0) {
      return self::LEVEL_NONE;
    }
    if ($score >= 9.0) {
      return self::LEVEL_CRITICAL;
    }
    if ($score >= 7.0) {
      return self::LEVEL_HIGH;
    }
    if ($score >= 4.0) {
      return self::LEVEL_MEDIUM;
    }
    return self::LEVEL_LOW;
  }

  /**
   * Extracts the NIS2 risk level from a single OSV vulnerability record.
   *
   * Checks the 'severity' array for CVSS_V3 score strings first, then falls
   * back to a text-based risk band mapping.
   *
   * @param array<string, mixed> $vuln
   *   A single OSV vulnerability object.
   *
   * @return string
   *   One of: 'critical', 'high', 'medium', 'low'.
   */
  private function riskLevelFromVuln(array $vuln): string {
    $cvssScore = $this->extractCvssScore($vuln);
    if ($cvssScore > 0.0) {
      return $this->levelFromCvssScore($cvssScore);
    }

    // Attempt text-based severity from OSV 'database_specific' or 'severity'.
    $textLevel = $this->extractTextSeverity($vuln);
    if ($textLevel !== '') {
      return $textLevel;
    }

    // Default: assume low risk when no score is available.
    return self::LEVEL_LOW;
  }

  /**
   * Extracts the highest CVSS v3 base score from a single OSV vulnerability.
   *
   * OSV severity objects look like: { "type": "CVSS_V3", "score": "CVSS:3.1/..." }
   * The score string encodes the base score as the last numeric segment after
   * the "BM:" or we parse the AV block. We use the numeric BM: segment which
   * is the base score itself encoded by NVD/GHSA in the vector string's
   * environmental-score position — however, OSV does not always include a
   * precomputed scalar. We therefore look for the CVSS:3.x/AV:... vector
   * and compute the approximate score, OR look for a 'cvss_v3' key in
   * 'database_specific' that many GHSA-sourced records include as a float.
   *
   * @param array<string, mixed> $vuln
   *   A single OSV vulnerability object.
   *
   * @return float
   *   The highest CVSS v3 base score found, or 0.0 if none.
   */
  private function extractCvssScore(array $vuln): float {
    $max = 0.0;

    // Check database_specific.cvss_v3 (GHSA sourced).
    $dbSpecific = $vuln['database_specific'] ?? [];
    if (is_array($dbSpecific)) {
      $cvssV3 = $dbSpecific['cvss_v3'] ?? $dbSpecific['cvss'] ?? NULL;
      if (is_numeric($cvssV3)) {
        $max = max($max, (float) $cvssV3);
      }
      // Some records store severity as a string label in database_specific.
      $severity = $dbSpecific['severity'] ?? '';
      if (is_string($severity)) {
        $levelScore = $this->textSeverityToScore($severity);
        $max = max($max, $levelScore);
      }
    }

    // Check the OSV 'severity' array for CVSS_V3 vector strings.
    $severityArray = $vuln['severity'] ?? [];
    if (is_array($severityArray)) {
      foreach ($severityArray as $sev) {
        if (!is_array($sev)) {
          continue;
        }
        $type = (string) ($sev['type'] ?? '');
        $scoreStr = (string) ($sev['score'] ?? '');

        if (in_array($type, ['CVSS_V3', 'CVSS_V4'], strict: true) && $scoreStr !== '') {
          $parsed = $this->parseCvssVectorScore($scoreStr);
          $max = max($max, $parsed);
        }
      }
    }

    // Check affected[].ecosystem_specific.severity if present.
    $affected = $vuln['affected'] ?? [];
    if (is_array($affected)) {
      foreach ($affected as $aff) {
        if (!is_array($aff)) {
          continue;
        }
        $ecosSev = $aff['ecosystem_specific']['severity'] ?? '';
        if (is_string($ecosSev) && $ecosSev !== '') {
          $max = max($max, $this->textSeverityToScore($ecosSev));
        }
      }
    }

    return $max;
  }

  /**
   * Parses a CVSS vector string and returns an approximate base score.
   *
   * When the vector itself does not embed the score (the base score is
   * not part of the CVSS:3.x/AV:... string), we return 0.0 and rely on
   * other fields. Some OSV records embed the score in the vector as a
   * separate prefix like "8.1 CVSS:3.1/AV:N..."; we extract that number.
   *
   * @param string $vectorString
   *   A CVSS vector string, possibly prefixed with a numeric score.
   *
   * @return float
   *   The extracted base score, or 0.0 if parsing fails.
   */
  private function parseCvssVectorScore(string $vectorString): float {
    // Pattern: optional "N.N " prefix before "CVSS:".
    if (preg_match('/^(\d+\.\d+)\s+CVSS:/i', $vectorString, $matches)) {
      return (float) $matches[1];
    }
    // Some records store just the numeric score.
    if (preg_match('/^(\d+\.\d+)$/', trim($vectorString), $matches)) {
      return (float) $matches[1];
    }
    return 0.0;
  }

  /**
   * Extracts a NIS2 risk level from text-based severity fields.
   *
   * Checks 'database_specific.severity' and 'affected[].ecosystem_specific.severity'.
   *
   * @param array<string, mixed> $vuln
   *   A single OSV vulnerability object.
   *
   * @return string
   *   A NIS2 level string, or empty string if not determinable.
   */
  private function extractTextSeverity(array $vuln): string {
    $dbSpecific = $vuln['database_specific'] ?? [];
    if (is_array($dbSpecific)) {
      $severity = (string) ($dbSpecific['severity'] ?? '');
      $level = $this->mapTextToLevel($severity);
      if ($level !== '') {
        return $level;
      }
    }

    $affected = $vuln['affected'] ?? [];
    if (is_array($affected)) {
      foreach ($affected as $aff) {
        if (!is_array($aff)) {
          continue;
        }
        $ecosSev = (string) ($aff['ecosystem_specific']['severity'] ?? '');
        $level = $this->mapTextToLevel($ecosSev);
        if ($level !== '') {
          return $level;
        }
      }
    }

    return '';
  }

  /**
   * Converts a text severity string to an approximate CVSS midpoint score.
   *
   * Used as a fallback when only text labels are available.
   *
   * @param string $text
   *   A severity label such as "CRITICAL", "HIGH", "MODERATE", "LOW".
   *
   * @return float
   *   A representative CVSS score (9.5, 7.5, 5.5, 2.0) or 0.0.
   */
  private function textSeverityToScore(string $text): float {
    return match (strtoupper(trim($text))) {
      'CRITICAL' => 9.5,
      'HIGH' => 7.5,
      'MODERATE', 'MEDIUM' => 5.5,
      'LOW' => 2.0,
      default => 0.0,
    };
  }

  /**
   * Maps a text severity label directly to a NIS2 risk level.
   *
   * @param string $text
   *   A severity label such as "CRITICAL", "HIGH", "MODERATE", "LOW".
   *
   * @return string
   *   A NIS2 level string, or empty string when the label is unrecognised.
   */
  private function mapTextToLevel(string $text): string {
    return match (strtoupper(trim($text))) {
      'CRITICAL' => self::LEVEL_CRITICAL,
      'HIGH' => self::LEVEL_HIGH,
      'MODERATE', 'MEDIUM' => self::LEVEL_MEDIUM,
      'LOW' => self::LEVEL_LOW,
      default => '',
    };
  }

  /**
   * Returns the more severe of two NIS2 risk level strings.
   *
   * @param string $a
   *   First risk level.
   * @param string $b
   *   Second risk level.
   *
   * @return string
   *   The higher-severity level.
   */
  private function maxLevel(string $a, string $b): string {
    $order = [
      self::LEVEL_NONE => 0,
      self::LEVEL_LOW => 1,
      self::LEVEL_MEDIUM => 2,
      self::LEVEL_HIGH => 3,
      self::LEVEL_CRITICAL => 4,
    ];

    return ($order[$a] ?? 0) >= ($order[$b] ?? 0) ? $a : $b;
  }

}
