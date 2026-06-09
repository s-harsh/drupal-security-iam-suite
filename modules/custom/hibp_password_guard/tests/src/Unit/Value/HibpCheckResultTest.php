<?php

declare(strict_types=1);

namespace Drupal\Tests\hibp_password_guard\Unit\Value;

use Drupal\hibp_password_guard\Value\HibpCheckResult;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for the HibpCheckResult value object.
 *
 * @coversDefaultClass \Drupal\hibp_password_guard\Value\HibpCheckResult
 * @group hibp_password_guard
 */
final class HibpCheckResultTest extends UnitTestCase {

  /**
   * @covers ::__construct
   */
  public function testConstructsWithRequiredPropertiesOnly(): void {
    $result = new HibpCheckResult(isPwned: true, breachCount: 100);

    $this->assertTrue($result->isPwned);
    $this->assertSame(100, $result->breachCount);
    // Optional params default to safe values.
    $this->assertFalse($result->apiError);
    $this->assertSame('', $result->errorType);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructsWithAllProperties(): void {
    $result = new HibpCheckResult(
      isPwned: true,
      breachCount: 42,
      apiError: true,
      errorType: 'SomeException',
    );

    $this->assertTrue($result->isPwned);
    $this->assertSame(42, $result->breachCount);
    $this->assertTrue($result->apiError);
    $this->assertSame('SomeException', $result->errorType);
  }

  /**
   * @covers ::__construct
   */
  public function testNotPwnedCleanResult(): void {
    $result = new HibpCheckResult(isPwned: false, breachCount: 0);

    $this->assertFalse($result->isPwned);
    $this->assertSame(0, $result->breachCount);
    $this->assertFalse($result->apiError);
    $this->assertSame('', $result->errorType);
  }

  /**
   * @covers ::__construct
   */
  public function testFailOpenApiError(): void {
    $result = new HibpCheckResult(
      isPwned: false,
      breachCount: 0,
      apiError: true,
      errorType: 'GuzzleHttp\\Exception\\ConnectException',
    );

    $this->assertFalse($result->isPwned);
    $this->assertTrue($result->apiError);
    $this->assertStringContainsString('ConnectException', $result->errorType);
  }

  /**
   * @covers ::__construct
   */
  public function testFailClosedApiError(): void {
    $result = new HibpCheckResult(
      isPwned: true,
      breachCount: 0,
      apiError: true,
      errorType: 'GuzzleHttp\\Exception\\ConnectException',
    );

    $this->assertTrue($result->isPwned);
    $this->assertSame(0, $result->breachCount);
    $this->assertTrue($result->apiError);
  }

  /**
   * @covers ::__construct
   *
   * The class must be declared readonly to guarantee immutability.
   */
  public function testClassIsReadonly(): void {
    $reflection = new \ReflectionClass(HibpCheckResult::class);
    $this->assertTrue($reflection->isReadOnly(), 'HibpCheckResult must be a readonly class.');
  }

  /**
   * @covers ::__construct
   */
  public function testBreachCountCanBeVeryLarge(): void {
    $result = new HibpCheckResult(isPwned: true, breachCount: PHP_INT_MAX);

    $this->assertSame(PHP_INT_MAX, $result->breachCount);
  }

  /**
   * @covers ::__construct
   */
  public function testErrorTypeCanContainExceptionClassName(): void {
    $className = 'GuzzleHttp\\Exception\\RequestException HTTP 500';
    $result = new HibpCheckResult(isPwned: false, breachCount: 0, apiError: true, errorType: $className);

    $this->assertSame($className, $result->errorType);
  }

}
