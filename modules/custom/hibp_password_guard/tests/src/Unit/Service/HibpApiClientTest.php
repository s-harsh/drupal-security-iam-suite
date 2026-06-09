<?php

declare(strict_types=1);

namespace Drupal\Tests\hibp_password_guard\Unit\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\hibp_password_guard\Service\HibpApiClient;
use Drupal\hibp_password_guard\Value\HibpRangeResponse;
use Drupal\Tests\UnitTestCase;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for HibpApiClient.
 *
 * @coversDefaultClass \Drupal\hibp_password_guard\Service\HibpApiClient
 * @group hibp_password_guard
 */
final class HibpApiClientTest extends UnitTestCase {

  /**
   * Default API base URL used by helper factory.
   */
  private const DEFAULT_BASE_URL = 'https://api.pwnedpasswords.com';

  /**
   * Default HTTP timeout used by helper factory.
   */
  private const DEFAULT_TIMEOUT = 5;

  /**
   * Creates a fully configured HibpApiClient with controlled dependencies.
   *
   * @param \GuzzleHttp\ClientInterface $httpClient
   *   The mock Guzzle HTTP client.
   * @param string $baseUrl
   *   API base URL to return from config.
   * @param int $timeout
   *   HTTP timeout to return from config.
   *
   * @return \Drupal\hibp_password_guard\Service\HibpApiClient
   */
  private function buildClient(
    ClientInterface $httpClient,
    string $baseUrl = self::DEFAULT_BASE_URL,
    int $timeout = self::DEFAULT_TIMEOUT,
  ): HibpApiClient {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['api_base_url', $baseUrl],
      ['http_timeout', $timeout],
    ]);

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')
      ->with('hibp_password_guard.settings')
      ->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);

    return new HibpApiClient($httpClient, $configFactory, $logger);
  }

  /**
   * Creates a mock HTTP response with a given status code and body string.
   */
  private function mockHttpResponse(int $statusCode, string $body = ''): ResponseInterface {
    $stream = $this->createMock(StreamInterface::class);
    $stream->method('getContents')->willReturn($body);

    $response = $this->createMock(ResponseInterface::class);
    $response->method('getStatusCode')->willReturn($statusCode);
    $response->method('getBody')->willReturn($stream);

    return $response;
  }

  // -------------------------------------------------------------------------
  // Successful response tests
  // -------------------------------------------------------------------------

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeReturnsSuccessOnHttp200(): void {
    $body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3533661\r\nABCDEF1234567890ABCDEF1234567890ABC:1";
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->mockHttpResponse(200, $body));

    $result = $this->buildClient($httpClient)->fetchRange('5BAA6');

    $this->assertInstanceOf(HibpRangeResponse::class, $result);
    $this->assertTrue($result->success);
    $this->assertSame(200, $result->statusCode);
    $this->assertSame($body, $result->body);
    $this->assertSame('', $result->errorMessage);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeBuildsCorrectUrlFromPrefixAndConfig(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $capturedUrl = '';

    $httpClient->expects($this->once())
      ->method('get')
      ->willReturnCallback(function (string $url, array $options) use (&$capturedUrl): ResponseInterface {
        $capturedUrl = $url;
        return $this->mockHttpResponse(200, 'DUMMY:1');
      });

    $this->buildClient($httpClient, 'https://api.pwnedpasswords.com')->fetchRange('5BAA6');

    $this->assertSame('https://api.pwnedpasswords.com/range/5BAA6', $capturedUrl);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeStripsTrailingSlashFromBaseUrl(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $capturedUrl = '';

    $httpClient->method('get')
      ->willReturnCallback(function (string $url, array $options) use (&$capturedUrl): ResponseInterface {
        $capturedUrl = $url;
        return $this->mockHttpResponse(200, 'DUMMY:1');
      });

    // Base URL has trailing slash — should be normalised.
    $this->buildClient($httpClient, 'https://api.pwnedpasswords.com/')->fetchRange('AAAAA');

    $this->assertSame('https://api.pwnedpasswords.com/range/AAAAA', $capturedUrl);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeSendsAddPaddingHeader(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $capturedOptions = [];

    $httpClient->method('get')
      ->willReturnCallback(function (string $url, array $options) use (&$capturedOptions): ResponseInterface {
        $capturedOptions = $options;
        return $this->mockHttpResponse(200, 'DUMMY:1');
      });

    $this->buildClient($httpClient)->fetchRange('00000');

    $this->assertArrayHasKey('headers', $capturedOptions);
    $this->assertArrayHasKey('Add-Padding', $capturedOptions['headers']);
    $this->assertSame('true', $capturedOptions['headers']['Add-Padding']);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeAppliesTimeoutFromConfig(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $capturedOptions = [];

    $httpClient->method('get')
      ->willReturnCallback(function (string $url, array $options) use (&$capturedOptions): ResponseInterface {
        $capturedOptions = $options;
        return $this->mockHttpResponse(200, 'DUMMY:1');
      });

    $this->buildClient($httpClient, self::DEFAULT_BASE_URL, 12)->fetchRange('AAAAA');

    $this->assertSame(12, $capturedOptions['timeout']);
    $this->assertSame(12, $capturedOptions['connect_timeout']);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeAppliesBothTimeoutKeysFromSameSetting(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $capturedOptions = [];

    $httpClient->method('get')
      ->willReturnCallback(function (string $url, array $options) use (&$capturedOptions): ResponseInterface {
        $capturedOptions = $options;
        return $this->mockHttpResponse(200, '');
      });

    $this->buildClient($httpClient, self::DEFAULT_BASE_URL, 7)->fetchRange('BBBBB');

    $this->assertSame($capturedOptions['timeout'], $capturedOptions['connect_timeout'],
      'timeout and connect_timeout must be set to the same value from config');
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeUppercasesThePrefix(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $capturedUrl = '';

    $httpClient->method('get')
      ->willReturnCallback(function (string $url, array $options) use (&$capturedUrl): ResponseInterface {
        $capturedUrl = $url;
        return $this->mockHttpResponse(200, 'DUMMY:1');
      });

    // Pass lowercase prefix — the client must uppercase it.
    $this->buildClient($httpClient)->fetchRange('5baa6');

    $this->assertStringContainsString('/range/5BAA6', $capturedUrl);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeReturnsFullBodyUnmodified(): void {
    $exactBody = "ABC00:100\r\nDEF11:200\r\nGHI22:0";
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->mockHttpResponse(200, $exactBody));

    $result = $this->buildClient($httpClient)->fetchRange('ZZZZZ');

    $this->assertSame($exactBody, $result->body);
  }

  // -------------------------------------------------------------------------
  // Non-200 HTTP status code tests
  // -------------------------------------------------------------------------

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeReturnsFailureOn429(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->mockHttpResponse(429, ''));

    $result = $this->buildClient($httpClient)->fetchRange('5BAA6');

    $this->assertFalse($result->success);
    $this->assertSame(429, $result->statusCode);
    $this->assertSame('', $result->body);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeReturnsFailureOn503(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->mockHttpResponse(503, ''));

    $result = $this->buildClient($httpClient)->fetchRange('5BAA6');

    $this->assertFalse($result->success);
    $this->assertSame(503, $result->statusCode);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeLogsNoticeOnNon200Status(): void {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['api_base_url', self::DEFAULT_BASE_URL],
      ['http_timeout', 5],
    ]);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())
      ->method('notice')
      ->with(
        $this->stringContains('@status'),
        $this->arrayHasKey('@status'),
      );

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->mockHttpResponse(429));

    $client = new HibpApiClient($httpClient, $configFactory, $logger);
    $client->fetchRange('5BAA6');
  }

  // -------------------------------------------------------------------------
  // ConnectException handling
  // -------------------------------------------------------------------------

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeCatchesConnectExceptionAndReturnsError(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('GET', 'https://api.pwnedpasswords.com/range/5BAA6');
    $httpClient->method('get')->willThrowException(
      new ConnectException('Connection refused', $request),
    );

    $result = $this->buildClient($httpClient)->fetchRange('5BAA6');

    $this->assertFalse($result->success);
    $this->assertSame(0, $result->statusCode);
    $this->assertStringContainsString('ConnectException', $result->errorMessage);
    $this->assertSame('', $result->body);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeLogsNoticeOnConnectException(): void {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['api_base_url', self::DEFAULT_BASE_URL],
      ['http_timeout', 5],
    ]);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())
      ->method('notice')
      ->with(
        $this->stringContains('connection failed'),
        $this->callback(function (array $context): bool {
          // Must NOT log a full 40-char SHA-1 hash.
          foreach ($context as $value) {
            if (is_string($value) && strlen($value) === 40 && ctype_xdigit($value)) {
              return false;
            }
          }
          return true;
        }),
      );

    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('GET', 'https://api.pwnedpasswords.com/range/5BAA6');
    $httpClient->method('get')->willThrowException(
      new ConnectException('Connection refused', $request),
    );

    $client = new HibpApiClient($httpClient, $configFactory, $logger);
    $client->fetchRange('5BAA6');
  }

  // -------------------------------------------------------------------------
  // RequestException handling
  // -------------------------------------------------------------------------

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeCatchesRequestExceptionWithoutResponse(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('GET', 'https://api.pwnedpasswords.com/range/5BAA6');
    $httpClient->method('get')->willThrowException(
      new RequestException('Server error', $request),
    );

    $result = $this->buildClient($httpClient)->fetchRange('5BAA6');

    $this->assertFalse($result->success);
    $this->assertSame(0, $result->statusCode);
    $this->assertStringContainsString('RequestException', $result->errorMessage);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeCatchesRequestExceptionWithHttpResponse(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('GET', 'https://api.pwnedpasswords.com/range/5BAA6');
    $httpResponse = new Response(500);
    $httpClient->method('get')->willThrowException(
      new RequestException('Internal server error', $request, $httpResponse),
    );

    $result = $this->buildClient($httpClient)->fetchRange('5BAA6');

    $this->assertFalse($result->success);
    $this->assertSame(500, $result->statusCode);
    $this->assertStringContainsString('RequestException', $result->errorMessage);
    $this->assertStringContainsString('500', $result->errorMessage);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeLogsNoticeOnRequestException(): void {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['api_base_url', self::DEFAULT_BASE_URL],
      ['http_timeout', 5],
    ]);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())
      ->method('notice')
      ->with(
        $this->stringContains('request failed'),
        $this->arrayHasKey('@status'),
      );

    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('GET', 'https://api.pwnedpasswords.com/range/5BAA6');
    $httpClient->method('get')->willThrowException(
      new RequestException('Server error', $request),
    );

    $client = new HibpApiClient($httpClient, $configFactory, $logger);
    $client->fetchRange('5BAA6');
  }

  // -------------------------------------------------------------------------
  // TransferException (generic) handling
  // -------------------------------------------------------------------------

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeCatchesGenericTransferException(): void {
    $httpClient = $this->createMock(ClientInterface::class);

    // Use an anonymous subclass of TransferException that is not
    // ConnectException or RequestException.
    $transferException = new class('Transfer error') extends TransferException {};
    $httpClient->method('get')->willThrowException($transferException);

    $result = $this->buildClient($httpClient)->fetchRange('5BAA6');

    $this->assertFalse($result->success);
    $this->assertSame(0, $result->statusCode);
    $this->assertNotEmpty($result->errorMessage);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeLogsNoticeOnTransferException(): void {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['api_base_url', self::DEFAULT_BASE_URL],
      ['http_timeout', 5],
    ]);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())
      ->method('notice')
      ->with($this->stringContains('transfer exception'));

    $httpClient = $this->createMock(ClientInterface::class);
    $transferException = new class('Transfer error') extends TransferException {};
    $httpClient->method('get')->willThrowException($transferException);

    $client = new HibpApiClient($httpClient, $configFactory, $logger);
    $client->fetchRange('CCCCC');
  }

  // -------------------------------------------------------------------------
  // Security: no password or hash data in logs
  // -------------------------------------------------------------------------

  /**
   * @covers ::fetchRange
   *
   * Security test: log context must never contain a full SHA-1 hash.
   */
  public function testFetchRangeNeverLogsFullSha1Hash(): void {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['api_base_url', self::DEFAULT_BASE_URL],
      ['http_timeout', 5],
    ]);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);

    // Capture all log calls and inspect context for 40-char hex strings.
    $logger->method('notice')
      ->willReturnCallback(function (string $message, array $context): void {
        foreach ($context as $key => $value) {
          if (is_string($value)) {
            $this->assertNotEquals(40, strlen($value),
              "Log context key '$key' contains a 40-char string that could be a SHA-1 hash.");
          }
        }
      });

    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('GET', 'https://api.pwnedpasswords.com/range/5BAA6');
    $httpClient->method('get')->willThrowException(
      new ConnectException('Connection refused', $request),
    );

    $client = new HibpApiClient($httpClient, $configFactory, $logger);
    $client->fetchRange('5BAA6');
  }

  // -------------------------------------------------------------------------
  // Config integration
  // -------------------------------------------------------------------------

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeRequestsCorrectConfigObject(): void {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['api_base_url', self::DEFAULT_BASE_URL],
      ['http_timeout', 5],
    ]);

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->expects($this->once())
      ->method('get')
      ->with('hibp_password_guard.settings')
      ->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('get')->willReturn($this->mockHttpResponse(200, 'DUMMY:1'));

    $client = new HibpApiClient($httpClient, $configFactory, $logger);
    $client->fetchRange('AAAAA');
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeWorksWithCustomBaseUrl(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $capturedUrl = '';
    $httpClient->method('get')
      ->willReturnCallback(function (string $url) use (&$capturedUrl): ResponseInterface {
        $capturedUrl = $url;
        return $this->mockHttpResponse(200, 'DUMMY:1');
      });

    $this->buildClient($httpClient, 'https://my-hibp-proxy.example.com')->fetchRange('DDDDD');

    $this->assertStringStartsWith('https://my-hibp-proxy.example.com/range/', $capturedUrl);
  }

  // -------------------------------------------------------------------------
  // Return type and value object shape
  // -------------------------------------------------------------------------

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeAlwaysReturnsHibpRangeResponseInstance(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('GET', 'https://api.pwnedpasswords.com/range/5BAA6');
    $httpClient->method('get')->willThrowException(
      new ConnectException('fail', $request),
    );

    $result = $this->buildClient($httpClient)->fetchRange('5BAA6');

    $this->assertInstanceOf(HibpRangeResponse::class, $result);
  }

  /**
   * @covers ::fetchRange
   */
  public function testFetchRangeErrorResponseHasEmptyBody(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('GET', 'https://api.pwnedpasswords.com/range/EEEEE');
    $httpClient->method('get')->willThrowException(
      new ConnectException('fail', $request),
    );

    $result = $this->buildClient($httpClient)->fetchRange('EEEEE');

    $this->assertSame('', $result->body);
  }

}
