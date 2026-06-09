<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Unit\Value;

use Drupal\api_flood_guard\Value\IpReputationResult;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for the IpReputationResult value object.
 *
 * @group api_flood_guard
 * @coversDefaultClass \Drupal\api_flood_guard\Value\IpReputationResult
 */
final class IpReputationResultTest extends UnitTestCase {

  /**
   * Tests that the constructor sets all properties correctly.
   *
   * @covers ::__construct
   */
  public function testConstructorSetsAllProperties(): void {
    $categories = [['category' => 18, 'reportedAt' => '2024-01-01']];
    $result = new IpReputationResult(
      isBlocked: TRUE,
      confidenceScore: 95,
      abuseCategories: $categories,
      providerName: 'abuseipdb',
      fromCache: TRUE,
      providerError: FALSE,
    );

    $this->assertTrue($result->isBlocked);
    $this->assertSame(95, $result->confidenceScore);
    $this->assertSame($categories, $result->abuseCategories);
    $this->assertSame('abuseipdb', $result->providerName);
    $this->assertTrue($result->fromCache);
    $this->assertFalse($result->providerError);
  }

  /**
   * Tests that optional constructor arguments default correctly.
   *
   * @covers ::__construct
   */
  public function testDefaultValues(): void {
    $result = new IpReputationResult(
      isBlocked: FALSE,
      confidenceScore: 0,
    );

    $this->assertFalse($result->isBlocked);
    $this->assertSame(0, $result->confidenceScore);
    $this->assertSame([], $result->abuseCategories);
    $this->assertSame('', $result->providerName);
    $this->assertFalse($result->fromCache);
    $this->assertFalse($result->providerError);
  }

  /**
   * Tests the failOpen() named constructor.
   *
   * @covers ::failOpen
   */
  public function testFailOpenSetsProviderError(): void {
    $result = IpReputationResult::failOpen('abuseipdb');

    $this->assertFalse($result->isBlocked);
    $this->assertTrue($result->providerError);
    $this->assertSame('abuseipdb', $result->providerName);
    $this->assertSame(0, $result->confidenceScore);
    $this->assertFalse($result->fromCache);
    $this->assertSame([], $result->abuseCategories);
  }

  /**
   * Tests failOpen() without a provider name.
   *
   * @covers ::failOpen
   */
  public function testFailOpenWithEmptyProviderName(): void {
    $result = IpReputationResult::failOpen();

    $this->assertSame('', $result->providerName);
    $this->assertTrue($result->providerError);
    $this->assertFalse($result->isBlocked);
  }

  /**
   * Tests the allowed() named constructor with all arguments.
   *
   * @covers ::allowed
   */
  public function testAllowedWithAllArguments(): void {
    $result = IpReputationResult::allowed(
      score: 42,
      providerName: 'abuseipdb',
      fromCache: TRUE,
    );

    $this->assertFalse($result->isBlocked);
    $this->assertSame(42, $result->confidenceScore);
    $this->assertSame('abuseipdb', $result->providerName);
    $this->assertTrue($result->fromCache);
    $this->assertFalse($result->providerError);
    $this->assertSame([], $result->abuseCategories);
  }

  /**
   * Tests the allowed() named constructor with default arguments.
   *
   * @covers ::allowed
   */
  public function testAllowedDefaults(): void {
    $result = IpReputationResult::allowed();

    $this->assertFalse($result->isBlocked);
    $this->assertSame(0, $result->confidenceScore);
    $this->assertSame('', $result->providerName);
    $this->assertFalse($result->fromCache);
    $this->assertFalse($result->providerError);
  }

  /**
   * Tests the blocked() named constructor.
   *
   * @covers ::blocked
   */
  public function testBlockedWithAllArguments(): void {
    $categories = [
      ['category' => 18, 'reportedAt' => '2024-01-01'],
      ['category' => 21, 'reportedAt' => '2024-01-02'],
    ];
    $result = IpReputationResult::blocked(
      score: 90,
      providerName: 'abuseipdb',
      categories: $categories,
      fromCache: TRUE,
    );

    $this->assertTrue($result->isBlocked);
    $this->assertSame(90, $result->confidenceScore);
    $this->assertSame('abuseipdb', $result->providerName);
    $this->assertSame($categories, $result->abuseCategories);
    $this->assertTrue($result->fromCache);
    $this->assertFalse($result->providerError);
  }

  /**
   * Tests blocked() with default fromCache (false).
   *
   * @covers ::blocked
   */
  public function testBlockedDefaultsFromCacheFalse(): void {
    $result = IpReputationResult::blocked(score: 95, providerName: 'abuseipdb');

    $this->assertTrue($result->isBlocked);
    $this->assertFalse($result->fromCache);
    $this->assertSame([], $result->abuseCategories);
  }

  /**
   * Tests that blocked() with score exactly at threshold (0 edge case).
   *
   * @covers ::blocked
   */
  public function testBlockedWithZeroScore(): void {
    $result = IpReputationResult::blocked(score: 0, providerName: 'test');

    $this->assertTrue($result->isBlocked);
    $this->assertSame(0, $result->confidenceScore);
  }

  /**
   * Tests that blocked() with maximum score (100) works correctly.
   *
   * @covers ::blocked
   */
  public function testBlockedWithMaxScore(): void {
    $result = IpReputationResult::blocked(score: 100, providerName: 'abuseipdb');

    $this->assertTrue($result->isBlocked);
    $this->assertSame(100, $result->confidenceScore);
  }

  /**
   * Tests that providerError and isBlocked can coexist (edge case verification).
   *
   * @covers ::__construct
   */
  public function testProviderErrorDoesNotImplyBlocked(): void {
    $result = IpReputationResult::failOpen('abuseipdb');

    // Fail-open means both providerError=true AND isBlocked=false.
    $this->assertTrue($result->providerError);
    $this->assertFalse($result->isBlocked);
  }

  /**
   * Tests that the value object is readonly (properties cannot be overwritten).
   *
   * @covers ::__construct
   */
  public function testReadonlyPropertyCannotBeModified(): void {
    $result = IpReputationResult::allowed(score: 10);

    $this->expectException(\Error::class);
    // @phpstan-ignore-next-line
    $result->isBlocked = TRUE;
  }

  /**
   * Tests that confidenceScore property is readonly.
   *
   * @covers ::__construct
   */
  public function testConfidenceScorePropertyIsReadonly(): void {
    $result = IpReputationResult::blocked(score: 80, providerName: 'abuseipdb');

    $this->expectException(\Error::class);
    // @phpstan-ignore-next-line
    $result->confidenceScore = 0;
  }

  /**
   * Tests that two different IpReputationResult instances are independent.
   *
   * @covers ::allowed
   * @covers ::blocked
   */
  public function testTwoInstancesAreIndependent(): void {
    $allowedResult = IpReputationResult::allowed(score: 30, providerName: 'abuseipdb');
    $blockedResult = IpReputationResult::blocked(score: 95, providerName: 'abuseipdb');

    $this->assertFalse($allowedResult->isBlocked);
    $this->assertTrue($blockedResult->isBlocked);
    $this->assertSame(30, $allowedResult->confidenceScore);
    $this->assertSame(95, $blockedResult->confidenceScore);
  }

}
