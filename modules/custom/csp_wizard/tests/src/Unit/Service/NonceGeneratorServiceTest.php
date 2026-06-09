<?php

declare(strict_types=1);

namespace Drupal\Tests\csp_wizard\Unit\Service;

use Drupal\Tests\UnitTestCase;
use Drupal\csp_wizard\Service\NonceGeneratorService;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Unit tests for NonceGeneratorService.
 *
 * @coversDefaultClass \Drupal\csp_wizard\Service\NonceGeneratorService
 * @group csp_wizard
 */
final class NonceGeneratorServiceTest extends UnitTestCase {

  /**
   * Creates a mock RequestStack with an optional current Request.
   *
   * @return array{RequestStack, Request|null}
   *   A tuple of [RequestStack mock, Request mock or null].
   */
  private function createRequestStack(?Request $request = NULL): RequestStack {
    $stack = $this->createMock(RequestStack::class);
    $stack->method('getCurrentRequest')->willReturn($request);
    return $stack;
  }

  /**
   * Creates a real Request with a real ParameterBag for attributes.
   */
  private function createRequest(): Request {
    $request = new Request();
    return $request;
  }

  /**
   * @covers ::getNonce
   */
  public function testGetNonceReturnsNonEmptyString(): void {
    $request = $this->createRequest();
    $stack = $this->createRequestStack($request);
    $service = new NonceGeneratorService($stack);

    $nonce = $service->getNonce();

    $this->assertNotEmpty($nonce);
    $this->assertIsString($nonce);
  }

  /**
   * @covers ::getNonce
   */
  public function testGetNonceReturnsSameValueOnSubsequentCalls(): void {
    $request = $this->createRequest();
    $stack = $this->createRequestStack($request);
    $service = new NonceGeneratorService($stack);

    $nonce1 = $service->getNonce();
    $nonce2 = $service->getNonce();

    $this->assertSame($nonce1, $nonce2, 'getNonce() must return the same nonce within a single request.');
  }

  /**
   * @covers ::getNonce
   */
  public function testNonceLengthCorrespondsTo32Bytes(): void {
    $request = $this->createRequest();
    $stack = $this->createRequestStack($request);
    $service = new NonceGeneratorService($stack);

    $nonce = $service->getNonce();

    // Base64url without padding: ceil(32 * 4/3) = 43 characters.
    $this->assertSame(43, strlen($nonce), 'Nonce must be exactly 43 characters (32 bytes Base64url-encoded without padding).');
  }

  /**
   * @covers ::getNonce
   */
  public function testNonceContainsOnlyBase64UrlCharacters(): void {
    $request = $this->createRequest();
    $stack = $this->createRequestStack($request);
    $service = new NonceGeneratorService($stack);

    $nonce = $service->getNonce();

    $this->assertMatchesRegularExpression(
      '/^[A-Za-z0-9\-_]+$/',
      $nonce,
      'Nonce must contain only Base64url characters (A-Z, a-z, 0-9, -, _).'
    );
  }

  /**
   * @covers ::resetNonce
   */
  public function testResetNonceClearsStoredNonce(): void {
    $request = $this->createRequest();
    $stack = $this->createRequestStack($request);
    $service = new NonceGeneratorService($stack);

    $nonce1 = $service->getNonce();
    $service->resetNonce();
    $nonce2 = $service->getNonce();

    $this->assertNotSame($nonce1, $nonce2, 'resetNonce() must cause the next getNonce() call to generate a fresh nonce.');
  }

  /**
   * @covers ::getNonce
   */
  public function testGetNonceWithNullRequestReturnsValue(): void {
    $stack = $this->createRequestStack(NULL);
    $service = new NonceGeneratorService($stack);

    // Should not throw when no current request is available.
    $nonce = $service->getNonce();
    $this->assertNotEmpty($nonce);
    $this->assertSame(43, strlen($nonce));
  }

}
