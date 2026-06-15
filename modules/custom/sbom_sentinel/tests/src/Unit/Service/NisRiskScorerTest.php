<?php

declare(strict_types=1);

namespace Drupal\Tests\sbom_sentinel\Unit\Service;

use Drupal\sbom_sentinel\Service\NisRiskScorer;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for NisRiskScorer.
 *
 * @coversDefaultClass \Drupal\sbom_sentinel\Service\NisRiskScorer
 * @group sbom_sentinel
 */
final class NisRiskScorerTest extends UnitTestCase {

  /**
   * The service under test.
   */
  private NisRiskScorer $scorer;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->scorer = new NisRiskScorer();
  }

  // -------------------------------------------------------------------------
  // computeRiskLevel() — empty / no vulnerabilities
  // -------------------------------------------------------------------------

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelReturnsNoneForEmptyList(): void {
    $this->assertSame(NisRiskScorer::LEVEL_NONE, $this->scorer->computeRiskLevel([]));
  }

  // -------------------------------------------------------------------------
  // computeRiskLevel() — CVSS v3 score ranges
  // -------------------------------------------------------------------------

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelReturnsCriticalForCvssAbove9(): void {
    $vuln = $this->makeVulnWithDbScore(9.8);
    $this->assertSame(NisRiskScorer::LEVEL_CRITICAL, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelReturnsCriticalForCvssExactly9(): void {
    $vuln = $this->makeVulnWithDbScore(9.0);
    $this->assertSame(NisRiskScorer::LEVEL_CRITICAL, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelReturnsHighForCvss8Point9(): void {
    $vuln = $this->makeVulnWithDbScore(8.9);
    $this->assertSame(NisRiskScorer::LEVEL_HIGH, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelReturnsHighForCvssExactly7(): void {
    $vuln = $this->makeVulnWithDbScore(7.0);
    $this->assertSame(NisRiskScorer::LEVEL_HIGH, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelReturnsMediumForCvss6Point9(): void {
    $vuln = $this->makeVulnWithDbScore(6.9);
    $this->assertSame(NisRiskScorer::LEVEL_MEDIUM, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelReturnsMediumForCvssExactly4(): void {
    $vuln = $this->makeVulnWithDbScore(4.0);
    $this->assertSame(NisRiskScorer::LEVEL_MEDIUM, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelReturnsLowForCvssBelow4(): void {
    $vuln = $this->makeVulnWithDbScore(3.9);
    $this->assertSame(NisRiskScorer::LEVEL_LOW, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelReturnsLowForCvssPoint1(): void {
    $vuln = $this->makeVulnWithDbScore(0.1);
    $this->assertSame(NisRiskScorer::LEVEL_LOW, $this->scorer->computeRiskLevel([$vuln]));
  }

  // -------------------------------------------------------------------------
  // computeRiskLevel() — multiple vulnerabilities, worst wins
  // -------------------------------------------------------------------------

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelReturnsWorstLevelAcrossMultipleVulns(): void {
    $vulns = [
      $this->makeVulnWithDbScore(3.0),  // low
      $this->makeVulnWithDbScore(5.5),  // medium
      $this->makeVulnWithDbScore(9.8),  // critical
      $this->makeVulnWithDbScore(7.5),  // high
    ];
    $this->assertSame(NisRiskScorer::LEVEL_CRITICAL, $this->scorer->computeRiskLevel($vulns));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelHighWhenNoVulnIsCritical(): void {
    $vulns = [
      $this->makeVulnWithDbScore(7.1),
      $this->makeVulnWithDbScore(8.8),
    ];
    $this->assertSame(NisRiskScorer::LEVEL_HIGH, $this->scorer->computeRiskLevel($vulns));
  }

  // -------------------------------------------------------------------------
  // computeRiskLevel() — text severity labels
  // -------------------------------------------------------------------------

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelHandlesTextCritical(): void {
    $vuln = ['id' => 'GHSA-xxxx', 'database_specific' => ['severity' => 'CRITICAL']];
    $this->assertSame(NisRiskScorer::LEVEL_CRITICAL, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelHandlesTextHigh(): void {
    $vuln = ['id' => 'GHSA-xxxx', 'database_specific' => ['severity' => 'HIGH']];
    $this->assertSame(NisRiskScorer::LEVEL_HIGH, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelHandlesTextModerate(): void {
    $vuln = ['id' => 'GHSA-xxxx', 'database_specific' => ['severity' => 'MODERATE']];
    $this->assertSame(NisRiskScorer::LEVEL_MEDIUM, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelHandlesTextLow(): void {
    $vuln = ['id' => 'GHSA-xxxx', 'database_specific' => ['severity' => 'LOW']];
    $this->assertSame(NisRiskScorer::LEVEL_LOW, $this->scorer->computeRiskLevel([$vuln]));
  }

  /**
   * @covers ::computeRiskLevel
   */
  public function testComputeRiskLevelHandlesUnknownTextSeverityAsLow(): void {
    $vuln = ['id' => 'GHSA-xxxx', 'database_specific' => ['severity' => 'UNRATED']];
    $this->assertSame(NisRiskScorer::LEVEL_LOW, $this->scorer->computeRiskLevel([$vuln]));
  }

  // -------------------------------------------------------------------------
  // maxCvssScore()
  // -------------------------------------------------------------------------

  /**
   * @covers ::maxCvssScore
   */
  public function testMaxCvssScoreReturnsZeroForEmptyList(): void {
    $this->assertSame(0.0, $this->scorer->maxCvssScore([]));
  }

  /**
   * @covers ::maxCvssScore
   */
  public function testMaxCvssScoreReturnsSingleScore(): void {
    $vuln = $this->makeVulnWithDbScore(7.5);
    $this->assertSame(7.5, $this->scorer->maxCvssScore([$vuln]));
  }

  /**
   * @covers ::maxCvssScore
   */
  public function testMaxCvssScoreReturnsHighestScore(): void {
    $vulns = [
      $this->makeVulnWithDbScore(4.0),
      $this->makeVulnWithDbScore(9.8),
      $this->makeVulnWithDbScore(6.5),
    ];
    $this->assertSame(9.8, $this->scorer->maxCvssScore($vulns));
  }

  /**
   * @covers ::maxCvssScore
   */
  public function testMaxCvssScoreHandlesVulnsWithoutScore(): void {
    $vuln = ['id' => 'GHSA-xxxx'];
    $this->assertSame(0.0, $this->scorer->maxCvssScore([$vuln]));
  }

  // -------------------------------------------------------------------------
  // levelFromCvssScore()
  // -------------------------------------------------------------------------

  /**
   * @covers ::levelFromCvssScore
   */
  public function testLevelFromCvssScoreZeroReturnsNone(): void {
    $this->assertSame(NisRiskScorer::LEVEL_NONE, $this->scorer->levelFromCvssScore(0.0));
  }

  /**
   * @covers ::levelFromCvssScore
   */
  public function testLevelFromCvssScoreNegativeReturnsNone(): void {
    $this->assertSame(NisRiskScorer::LEVEL_NONE, $this->scorer->levelFromCvssScore(-1.0));
  }

  /**
   * @covers ::levelFromCvssScore
   */
  public function testLevelFromCvssScore9Point0ReturnsCritical(): void {
    $this->assertSame(NisRiskScorer::LEVEL_CRITICAL, $this->scorer->levelFromCvssScore(9.0));
  }

  /**
   * @covers ::levelFromCvssScore
   */
  public function testLevelFromCvssScore10ReturnsMaxSeverity(): void {
    $this->assertSame(NisRiskScorer::LEVEL_CRITICAL, $this->scorer->levelFromCvssScore(10.0));
  }

  /**
   * @covers ::levelFromCvssScore
   */
  public function testLevelFromCvssScore7ReturnsHigh(): void {
    $this->assertSame(NisRiskScorer::LEVEL_HIGH, $this->scorer->levelFromCvssScore(7.0));
  }

  /**
   * @covers ::levelFromCvssScore
   */
  public function testLevelFromCvssScore8Point9ReturnsHigh(): void {
    $this->assertSame(NisRiskScorer::LEVEL_HIGH, $this->scorer->levelFromCvssScore(8.9));
  }

  /**
   * @covers ::levelFromCvssScore
   */
  public function testLevelFromCvssScore4ReturnsMedium(): void {
    $this->assertSame(NisRiskScorer::LEVEL_MEDIUM, $this->scorer->levelFromCvssScore(4.0));
  }

  /**
   * @covers ::levelFromCvssScore
   */
  public function testLevelFromCvssScore6Point9ReturnsMedium(): void {
    $this->assertSame(NisRiskScorer::LEVEL_MEDIUM, $this->scorer->levelFromCvssScore(6.9));
  }

  /**
   * @covers ::levelFromCvssScore
   */
  public function testLevelFromCvssScore3Point9ReturnsLow(): void {
    $this->assertSame(NisRiskScorer::LEVEL_LOW, $this->scorer->levelFromCvssScore(3.9));
  }

  /**
   * @covers ::levelFromCvssScore
   */
  public function testLevelFromCvssScore0Point1ReturnsLow(): void {
    $this->assertSame(NisRiskScorer::LEVEL_LOW, $this->scorer->levelFromCvssScore(0.1));
  }

  // -------------------------------------------------------------------------
  // Level constants
  // -------------------------------------------------------------------------

  /**
   * @covers ::computeRiskLevel
   */
  public function testLevelConstantsHaveExpectedValues(): void {
    $this->assertSame('critical', NisRiskScorer::LEVEL_CRITICAL);
    $this->assertSame('high', NisRiskScorer::LEVEL_HIGH);
    $this->assertSame('medium', NisRiskScorer::LEVEL_MEDIUM);
    $this->assertSame('low', NisRiskScorer::LEVEL_LOW);
    $this->assertSame('none', NisRiskScorer::LEVEL_NONE);
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /**
   * Creates a minimal vulnerability record with a cvss_v3 score in database_specific.
   *
   * @param float $score
   *   The CVSS v3 base score.
   *
   * @return array<string, mixed>
   *   A minimal OSV vulnerability record.
   */
  private function makeVulnWithDbScore(float $score): array {
    return [
      'id' => 'GHSA-test-' . (int) ($score * 10),
      'summary' => 'Test vulnerability with score ' . $score,
      'database_specific' => [
        'cvss_v3' => $score,
      ],
    ];
  }

}
