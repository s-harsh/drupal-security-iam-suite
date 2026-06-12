<?php

declare(strict_types=1);

namespace Drupal\Tests\sbom_sentinel\Unit\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\sbom_sentinel\Service\OsvApiClient;
use Drupal\sbom_sentinel\Value\SbomComponent;
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
 * Unit tests for OsvApiClient.
 *
 * @coversDefaultClass \Drupal\sbom_sentinel\Service\OsvApiClient
 * @group sbom_sentinel
 */
final class OsvApiClientTest extends UnitTestCase {

  /**
   * Default OSV base URL used by helper factory.
   */
  private const DEFAULT_BASE_URL = 'https://api.osv.dev/v1';

  /**
   * Default HTTP timeout.
   */
  private const DEFAULT_TIMEOUT = 10;

  /**
   * Creates a configured OsvApiClient with controlled dependencies.
   *
   * @param \GuzzleHttp\ClientInterface $httpClient
   *   The mock Guzzle HTTP client.
   * @param string $baseUrl
   *   API base URL to return from config.
   * @param int $timeout
   *   HTTP timeout to return from config.
   *
   * @return \Drupal\sbom_sentinel\Service\OsvApiClient
   */
  private function buildClient(
    ClientInterface $httpClient,
    string $baseUrl = self::DEFAULT_BASE_URL,
    int $timeout = self::DEFAULT_TIMEOUT,
  ): OsvApiClient {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['osv_api_base_url', $baseUrl],
      ['http_timeout', $timeout],
    ]);

    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')
      ->with('sbom_sentinel.settings')
      ->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);

    return new OsvApiClient($httpClient, $configFactory, $logger);
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

  /**
   * Creates a minimal SbomComponent for testing.
   */
  private function makeComponent(
    string $name = 'drupal/core',
    string $version = '11.1.0',
  ): SbomComponent {
    return new SbomComponent(
      name: $name,
      version: $version,
      type: 'drupal-core',
      description: '',
      purl: 'pkg:composer/' . $name . '@' . $version,
      bomRef: md5($name . $version),
      licenses: [],
      sourceUrl: '',
    );
  }

  // -------------------------------------------------------------------------
  // Successful response
  // -------------------------------------------------------------------------

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentReturnsSuccessOnHttp200WithVulns(): void {
    $body = json_encode([
      'vulns' => [
        ['id' => 'GHSA-test-0001', 'summary' => 'Test vuln'],
      ],
    ]);
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('post')->willReturn($this->mockHttpResponse(200, $body));

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertTrue($result['success']);
    $this->assertCount(1, $result['vulnerabilities']);
    $this->assertSame('', $result['error_message']);
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentReturnsEmptyVulnsWhenNoneFound(): void {
    $body = json_encode(['vulns' => []]);
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('post')->willReturn($this->mockHttpResponse(200, $body));

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertTrue($result['success']);
    $this->assertSame([], $result['vulnerabilities']);
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentHandlesMissingVulnsKey(): void {
    $body = json_encode([]);
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('post')->willReturn($this->mockHttpResponse(200, $body));

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertTrue($result['success']);
    $this->assertSame([], $result['vulnerabilities']);
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentBuildsCorrectUrl(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $capturedUrl = '';

    $httpClient->method('post')
      ->willReturnCallback(function (string $url) use (&$capturedUrl): ResponseInterface {
        $capturedUrl = $url;
        return $this->mockHttpResponse(200, json_encode(['vulns' => []]));
      });

    $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertSame('https://api.osv.dev/v1/query', $capturedUrl);
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentStripsTrailingSlashFromBaseUrl(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $capturedUrl = '';

    $httpClient->method('post')
      ->willReturnCallback(function (string $url) use (&$capturedUrl): ResponseInterface {
        $capturedUrl = $url;
        return $this->mockHttpResponse(200, json_encode(['vulns' => []]));
      });

    $this->buildClient($httpClient, 'https://api.osv.dev/v1/')->queryComponent($this->makeComponent());

    $this->assertSame('https://api.osv.dev/v1/query', $capturedUrl);
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentSendsPackagenameAndVersionInPayload(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $capturedOptions = [];

    $httpClient->method('post')
      ->willReturnCallback(function (string $url, array $options) use (&$capturedOptions): ResponseInterface {
        $capturedOptions = $options;
        return $this->mockHttpResponse(200, json_encode(['vulns' => []]));
      });

    $component = $this->makeComponent(name: 'drupal/node', version: '11.0.5');
    $this->buildClient($httpClient)->queryComponent($component);

    $this->assertArrayHasKey('json', $capturedOptions);
    $payload = $capturedOptions['json'];
    $this->assertSame('11.0.5', $payload['version']);
    $this->assertSame('drupal/node', $payload['package']['name']);
    $this->assertSame('Packagist', $payload['package']['ecosystem']);
  }

  // -------------------------------------------------------------------------
  // Non-200 HTTP responses
  // -------------------------------------------------------------------------

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentReturnsFailureOn429(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('post')->willReturn($this->mockHttpResponse(429, ''));

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertFalse($result['success']);
    $this->assertStringContainsString('429', $result['error_message']);
    $this->assertSame([], $result['vulnerabilities']);
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentLogsNoticeOnNon200(): void {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['osv_api_base_url', self::DEFAULT_BASE_URL],
      ['http_timeout', 10],
    ]);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->willReturn($config);

    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())
      ->method('notice')
      ->with($this->stringContains('@status'), $this->arrayHasKey('@status'));

    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('post')->willReturn($this->mockHttpResponse(503, ''));

    $client = new OsvApiClient($httpClient, $configFactory, $logger);
    $client->queryComponent($this->makeComponent());
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentReturnsFailureOnInvalidJson(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $httpClient->method('post')->willReturn($this->mockHttpResponse(200, 'not-json'));

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertFalse($result['success']);
    $this->assertStringContainsString('Invalid JSON', $result['error_message']);
  }

  // -------------------------------------------------------------------------
  // Exception handling
  // -------------------------------------------------------------------------

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentCatchesConnectException(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('POST', self::DEFAULT_BASE_URL . '/query');
    $httpClient->method('post')->willThrowException(new ConnectException('refused', $request));

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertFalse($result['success']);
    $this->assertStringContainsString('ConnectException', $result['error_message']);
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentCatchesRequestException(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('POST', self::DEFAULT_BASE_URL . '/query');
    $httpClient->method('post')->willThrowException(new RequestException('error', $request));

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertFalse($result['success']);
    $this->assertStringContainsString('RequestException', $result['error_message']);
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentCatchesRequestExceptionWithResponse(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('POST', self::DEFAULT_BASE_URL . '/query');
    $httpResponse = new Response(500);
    $httpClient->method('post')->willThrowException(
      new RequestException('server error', $request, $httpResponse),
    );

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertFalse($result['success']);
    $this->assertStringContainsString('500', $result['error_message']);
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentCatchesTransferException(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $transferException = new class('Transfer error') extends TransferException {};
    $httpClient->method('post')->willThrowException($transferException);

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertFalse($result['success']);
    $this->assertSame([], $result['vulnerabilities']);
    $this->assertNotEmpty($result['error_message']);
  }

  // -------------------------------------------------------------------------
  // Return type invariants
  // -------------------------------------------------------------------------

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentAlwaysReturnsArrayWithRequiredKeys(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('POST', self::DEFAULT_BASE_URL . '/query');
    $httpClient->method('post')->willThrowException(new ConnectException('fail', $request));

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertArrayHasKey('success', $result);
    $this->assertArrayHasKey('vulnerabilities', $result);
    $this->assertArrayHasKey('error_message', $result);
  }

  /**
   * @covers ::queryComponent
   */
  public function testQueryComponentVulnerabilitiesIsAlwaysArray(): void {
    $httpClient = $this->createMock(ClientInterface::class);
    $request = new Request('POST', self::DEFAULT_BASE_URL . '/query');
    $httpClient->method('post')->willThrowException(new ConnectException('fail', $request));

    $result = $this->buildClient($httpClient)->queryComponent($this->makeComponent());

    $this->assertIsArray($result['vulnerabilities']);
  }

}
