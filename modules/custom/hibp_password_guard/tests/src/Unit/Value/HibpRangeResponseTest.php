<?php

declare(strict_types=1);

namespace Drupal\Tests\hibp_password_guard\Unit\Value;

use Drupal\hibp_password_guard\Value\HibpRangeResponse;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for the HibpRangeResponse value object.
 *
 * @coversDefaultClass \Drupal\hibp_password_guard\Value\HibpRangeResponse
 * @group hibp_password_guard
 */
final class HibpRangeResponseTest extends UnitTestCase {

  /**
   * @covers ::__construct
   */
  public function testConstructsSuccessResponse(): void {
    $body = "ABC00:100\r\nDEF11:200";
    $response = new HibpRangeResponse(success: true, body: $body, statusCode: 200);

    $this->assertTrue($response->success);
    $this->assertSame($body, $response->body);
    $this->assertSame(200, $response->statusCode);
    $this->assertSame('', $response->errorMessage);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructsConnectionErrorResponse(): void {
    $response = new HibpRangeResponse(
      success: false,
      statusCode: 0,
      errorMessage: 'GuzzleHttp\\Exception\\ConnectException',
    );

    $this->assertFalse($response->success);
    $this->assertSame('', $response->body);
    $this->assertSame(0, $response->statusCode);
    $this->assertStringContainsString('ConnectException', $response->errorMessage);
  }

  /**
   * @covers ::__construct
   */
  public function testConstructsHttpErrorResponse(): void {
    $response = new HibpRangeResponse(
      success: false,
      statusCode: 429,
      errorMessage: 'HTTP 429',
    );

    $this->assertFalse($response->success);
    $this->assertSame(429, $response->statusCode);
    $this->assertSame('HTTP 429', $response->errorMessage);
    $this->assertSame('', $response->body);
  }

  /**
   * @covers ::__construct
   */
  public function testDefaultsForOptionalParameters(): void {
    $response = new HibpRangeResponse(success: true);

    $this->assertSame('', $response->body);
    $this->assertSame(0, $response->statusCode);
    $this->assertSame('', $response->errorMessage);
  }

  /**
   * @covers ::__construct
   *
   * The class must be declared readonly to guarantee immutability.
   */
  public function testClassIsReadonly(): void {
    $reflection = new \ReflectionClass(HibpRangeResponse::class);
    $this->assertTrue($reflection->isReadOnly(), 'HibpRangeResponse must be a readonly class.');
  }

  /**
   * @covers ::__construct
   */
  public function testBodyCanContainCrlfDelimitedLines(): void {
    $body = "SUFFIX1:100\r\nSUFFIX2:200\r\nSUFFIX3:0";
    $response = new HibpRangeResponse(success: true, body: $body, statusCode: 200);

    $this->assertStringContainsString("\r\n", $response->body);
    $lines = explode("\r\n", $response->body);
    $this->assertCount(3, $lines);
  }

  /**
   * @covers ::__construct
   */
  public function testStatusCodeZeroSignalsConnectionLevelFailure(): void {
    $response = new HibpRangeResponse(success: false, statusCode: 0, errorMessage: 'ConnectException');

    $this->assertSame(0, $response->statusCode);
    $this->assertFalse($response->success);
  }

}
