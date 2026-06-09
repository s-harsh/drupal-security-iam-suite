<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Unit\EventSubscriber;

use Drupal\api_flood_guard\EventSubscriber\ApiFloodSubscriber;
use Drupal\api_flood_guard\Service\ApiEndpointDetector;
use Drupal\api_flood_guard\Service\ApiFloodManager;
use Drupal\api_flood_guard\Value\FloodDecision;
use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Unit tests for ApiFloodSubscriber.
 *
 * @group api_flood_guard
 * @coversDefaultClass \Drupal\api_flood_guard\EventSubscriber\ApiFloodSubscriber
 */
final class ApiFloodSubscriberTest extends UnitTestCase {

  /**
   * Builds a ConfigFactoryInterface mock with the given settings.
   */
  private function buildConfigFactory(array $settings = []): ConfigFactoryInterface {
    $defaults = [
      'response_code'  => 429,
      'block_message'  => 'Too many authentication requests. Please wait before trying again.',
      'ip_window'      => 3600,
    ];
    $merged = array_merge($defaults, $settings);

    $config = $this->createMock(Config::class);
    $config->method('get')
      ->willReturnCallback(static function (string $key) use ($merged) {
        return $merged[$key] ?? NULL;
      });

    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->willReturn($config);
    return $factory;
  }

  /**
   * Builds an ApiFloodSubscriber with mocked collaborators.
   */
  private function buildSubscriber(
    ?ApiFloodManager $floodManager = NULL,
    ?ApiEndpointDetector $detector = NULL,
    ?ConfigFactoryInterface $configFactory = NULL,
    ?LoggerInterface $logger = NULL,
  ): ApiFloodSubscriber {
    $floodManager ??= $this->createMock(ApiFloodManager::class);
    $detector ??= $this->createMock(ApiEndpointDetector::class);
    $configFactory ??= $this->buildConfigFactory();
    $logger ??= $this->createMock(LoggerInterface::class);

    return new ApiFloodSubscriber($floodManager, $detector, $configFactory, $logger);
  }

  /**
   * Builds a RequestEvent for tests.
   */
  private function buildRequestEvent(Request $request, bool $isMainRequest = TRUE): RequestEvent {
    $kernel = $this->createMock(HttpKernelInterface::class);
    $requestType = $isMainRequest ? HttpKernelInterface::MAIN_REQUEST : HttpKernelInterface::SUB_REQUEST;
    return new RequestEvent($kernel, $request, $requestType);
  }

  /**
   * Builds a ResponseEvent for tests.
   */
  private function buildResponseEvent(Request $request, Response $response, bool $isMainRequest = TRUE): ResponseEvent {
    $kernel = $this->createMock(HttpKernelInterface::class);
    $requestType = $isMainRequest ? HttpKernelInterface::MAIN_REQUEST : HttpKernelInterface::SUB_REQUEST;
    return new ResponseEvent($kernel, $request, $requestType, $response);
  }

  // -------------------------------------------------------------------------
  // getSubscribedEvents()
  // -------------------------------------------------------------------------

  /**
   * Tests that the subscriber registers REQUEST and RESPONSE event listeners.
   *
   * @covers ::getSubscribedEvents
   */
  public function testGetSubscribedEventsRegistersRequestAndResponse(): void {
    $events = ApiFloodSubscriber::getSubscribedEvents();

    $this->assertArrayHasKey(KernelEvents::REQUEST, $events);
    $this->assertArrayHasKey(KernelEvents::RESPONSE, $events);
  }

  /**
   * Tests that the REQUEST listener runs at priority 300.
   *
   * @covers ::getSubscribedEvents
   */
  public function testRequestListenerRunsAtPriority300(): void {
    $events = ApiFloodSubscriber::getSubscribedEvents();
    $requestListeners = $events[KernelEvents::REQUEST];

    // Find the onRequest listener and check its priority.
    $found = FALSE;
    foreach ($requestListeners as $listener) {
      if ($listener[0] === 'onRequest') {
        $this->assertSame(300, $listener[1]);
        $found = TRUE;
      }
    }
    $this->assertTrue($found, 'onRequest listener should be registered at priority 300');
  }

  /**
   * Tests that the RESPONSE listener runs at priority -100.
   *
   * @covers ::getSubscribedEvents
   */
  public function testResponseListenerRunsAtPriorityMinus100(): void {
    $events = ApiFloodSubscriber::getSubscribedEvents();
    $responseListeners = $events[KernelEvents::RESPONSE];

    $found = FALSE;
    foreach ($responseListeners as $listener) {
      if ($listener[0] === 'onResponse') {
        $this->assertSame(-100, $listener[1]);
        $found = TRUE;
      }
    }
    $this->assertTrue($found, 'onResponse listener should be registered at priority -100');
  }

  // -------------------------------------------------------------------------
  // onRequest() — early-exit conditions
  // -------------------------------------------------------------------------

  /**
   * Tests that sub-requests are ignored.
   *
   * @covers ::onRequest
   */
  public function testSubRequestIsIgnored(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->expects($this->never())->method('isProtectedPath');

    $subscriber = $this->buildSubscriber(detector: $detector);
    $event = $this->buildRequestEvent(Request::create('/user/login'), isMainRequest: FALSE);

    $subscriber->onRequest($event);
    $this->assertNull($event->getResponse()); // No response should have been set.
  }

  /**
   * Tests that non-protected paths are ignored.
   *
   * @covers ::onRequest
   */
  public function testNonProtectedPathIsIgnored(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(FALSE);

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->expects($this->never())->method('evaluate');

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildRequestEvent(Request::create('/node/1'));

    $subscriber->onRequest($event);
    $this->assertNull($event->getResponse());
  }

  /**
   * Tests that HTML form submissions are ignored.
   *
   * @covers ::onRequest
   */
  public function testHtmlFormSubmissionIsIgnored(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('isHtmlFormSubmission')->willReturn(TRUE);

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->expects($this->never())->method('evaluate');

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $request = Request::create('/user/login', 'POST', [], [], [], [
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
    ]);
    $event = $this->buildRequestEvent($request);

    $subscriber->onRequest($event);
    $this->assertNull($event->getResponse());
  }

  // -------------------------------------------------------------------------
  // onRequest() — flood decision outcomes
  // -------------------------------------------------------------------------

  /**
   * Tests that an allowed flood decision does NOT set a response on the event.
   *
   * @covers ::onRequest
   */
  public function testAllowedDecisionDoesNotSetResponse(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('isHtmlFormSubmission')->willReturn(FALSE);
    $detector->method('extractUsernameIdentifier')->willReturn('');

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->method('evaluate')
      ->willReturn(FloodDecision::pass('1.2.3.4'));

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildRequestEvent(Request::create('/user/login'));

    $subscriber->onRequest($event);
    $this->assertNull($event->getResponse());
  }

  /**
   * Tests that a blocked flood decision sets a 429 response.
   *
   * @covers ::onRequest
   */
  public function testBlockedDecisionSets429Response(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('isHtmlFormSubmission')->willReturn(FALSE);
    $detector->method('extractUsernameIdentifier')->willReturn('');

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->method('evaluate')
      ->willReturn(FloodDecision::block(reason: 'ip', identifier: '1.2.3.4', retryAfter: 3600));

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildRequestEvent(Request::create('/user/login'));

    $subscriber->onRequest($event);

    $response = $event->getResponse();
    $this->assertNotNull($response);
    $this->assertSame(429, $response->getStatusCode());
  }

  /**
   * Tests that the block response includes the Retry-After header.
   *
   * @covers ::onRequest
   */
  public function testBlockedResponseIncludesRetryAfterHeader(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('isHtmlFormSubmission')->willReturn(FALSE);
    $detector->method('extractUsernameIdentifier')->willReturn('');

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->method('evaluate')
      ->willReturn(FloodDecision::block(reason: 'ip', identifier: '1.2.3.4', retryAfter: 1800));

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildRequestEvent(Request::create('/user/login'));
    $subscriber->onRequest($event);

    $response = $event->getResponse();
    $this->assertNotNull($response);
    $this->assertSame('1800', $response->headers->get('Retry-After'));
  }

  /**
   * Tests that a JSON-accepting client receives a JSON response body.
   *
   * @covers ::onRequest
   */
  public function testJsonAcceptHeaderReturnsJsonBody(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('isHtmlFormSubmission')->willReturn(FALSE);
    $detector->method('extractUsernameIdentifier')->willReturn('');

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->method('evaluate')
      ->willReturn(FloodDecision::block(reason: 'ip', identifier: '1.2.3.4', retryAfter: 3600));

    $request = Request::create('/user/login', 'POST', [], [], [], [
      'HTTP_ACCEPT' => 'application/json',
    ]);

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildRequestEvent($request);
    $subscriber->onRequest($event);

    $response = $event->getResponse();
    $this->assertNotNull($response);
    $decoded = json_decode($response->getContent(), TRUE);
    $this->assertIsArray($decoded);
    $this->assertArrayHasKey('errors', $decoded);
    $this->assertSame('429', $decoded['errors'][0]['status']);
  }

  /**
   * Tests that a vnd.api+json Accept header also returns a JSON:API body.
   *
   * @covers ::onRequest
   */
  public function testVndApiJsonAcceptHeaderReturnsJsonBody(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('isHtmlFormSubmission')->willReturn(FALSE);
    $detector->method('extractUsernameIdentifier')->willReturn('');

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->method('evaluate')
      ->willReturn(FloodDecision::block(reason: 'ip', identifier: '1.2.3.4', retryAfter: 3600));

    $request = Request::create('/jsonapi/node/article', 'POST', [], [], [], [
      'HTTP_ACCEPT' => 'application/vnd.api+json',
    ]);

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildRequestEvent($request);
    $subscriber->onRequest($event);

    $response = $event->getResponse();
    $this->assertNotNull($response);
    $body = json_decode($response->getContent(), TRUE);
    $this->assertArrayHasKey('errors', $body);
  }

  /**
   * Tests that a non-JSON client receives a plain-text response.
   *
   * @covers ::onRequest
   */
  public function testNonJsonClientReceivesPlainTextResponse(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('isHtmlFormSubmission')->willReturn(FALSE);
    $detector->method('extractUsernameIdentifier')->willReturn('');

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->method('evaluate')
      ->willReturn(FloodDecision::block(reason: 'ip', identifier: '1.2.3.4', retryAfter: 3600));

    $request = Request::create('/user/login', 'POST', [], [], [], [
      'HTTP_ACCEPT' => 'text/html,application/xhtml+xml',
    ]);

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildRequestEvent($request);
    $subscriber->onRequest($event);

    $response = $event->getResponse();
    $this->assertNotNull($response);
    $contentType = $response->headers->get('Content-Type');
    $this->assertStringContainsString('text/plain', $contentType);
    $this->assertStringContainsString('Too many authentication requests', $response->getContent());
  }

  /**
   * Tests that a 503 response code config results in 503 status.
   *
   * @covers ::onRequest
   */
  public function testConfigured503ResponseCodeResults503(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('isHtmlFormSubmission')->willReturn(FALSE);
    $detector->method('extractUsernameIdentifier')->willReturn('');

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->method('evaluate')
      ->willReturn(FloodDecision::block(reason: 'ip', identifier: '1.2.3.4', retryAfter: 3600));

    $subscriber = $this->buildSubscriber(
      floodManager: $floodManager,
      detector: $detector,
      configFactory: $this->buildConfigFactory(['response_code' => 503]),
    );

    $request = Request::create('/user/login', 'POST', [], [], [], [
      'HTTP_ACCEPT' => 'application/json',
    ]);
    $event = $this->buildRequestEvent($request);
    $subscriber->onRequest($event);

    $response = $event->getResponse();
    $this->assertNotNull($response);
    $this->assertSame(503, $response->getStatusCode());
    $decoded = json_decode($response->getContent(), TRUE);
    $this->assertSame('503', $decoded['errors'][0]['status']);
    $this->assertSame('Service Unavailable', $decoded['errors'][0]['title']);
  }

  /**
   * Tests that the block response includes Cache-Control: no-store.
   *
   * @covers ::onRequest
   */
  public function testBlockedResponseHasCacheControlNoStore(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('isHtmlFormSubmission')->willReturn(FALSE);
    $detector->method('extractUsernameIdentifier')->willReturn('');

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->method('evaluate')
      ->willReturn(FloodDecision::block(reason: 'ip', identifier: '5.5.5.5', retryAfter: 3600));

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildRequestEvent(Request::create('/user/login'));
    $subscriber->onRequest($event);

    $response = $event->getResponse();
    $this->assertNotNull($response);
    $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
  }

  // -------------------------------------------------------------------------
  // onResponse() — flood counter clearing
  // -------------------------------------------------------------------------

  /**
   * Tests that sub-responses are ignored in onResponse.
   *
   * @covers ::onResponse
   */
  public function testSubResponseIsIgnoredInOnResponse(): void {
    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->expects($this->never())->method('clearUserFlood');

    $subscriber = $this->buildSubscriber(floodManager: $floodManager);
    $request = Request::create('/user/login');
    $response = new Response('', 200);
    $event = $this->buildResponseEvent($request, $response, isMainRequest: FALSE);

    $subscriber->onResponse($event);
  }

  /**
   * Tests that non-protected paths are ignored in onResponse.
   *
   * @covers ::onResponse
   */
  public function testNonProtectedPathIgnoredInOnResponse(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(FALSE);

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->expects($this->never())->method('clearUserFlood');

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildResponseEvent(Request::create('/node/1'), new Response('', 200));

    $subscriber->onResponse($event);
  }

  /**
   * Tests that a non-200 response does NOT clear user flood counters.
   *
   * @covers ::onResponse
   */
  public function testNon200ResponseDoesNotClearUserFlood(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->expects($this->never())->method('clearUserFlood');

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildResponseEvent(
      Request::create('/user/login'),
      new Response('Unauthorized', 401),
    );

    $subscriber->onResponse($event);
  }

  /**
   * Tests that a 200 response to a protected path clears the user flood counter.
   *
   * @covers ::onResponse
   */
  public function testSuccessResponseClearsUserFloodCounter(): void {
    $usernameHash = hash('sha256', 'admin');

    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('extractUsernameIdentifier')->willReturn($usernameHash);

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->expects($this->once())
      ->method('clearUserFlood')
      ->with($usernameHash);

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildResponseEvent(
      Request::create('/user/login'),
      new Response('OK', 200),
    );

    $subscriber->onResponse($event);
  }

  /**
   * Tests that an empty username hash on 200 does NOT call clearUserFlood.
   *
   * @covers ::onResponse
   */
  public function testSuccessResponseWithNoUsernameDoesNotClearFlood(): void {
    $detector = $this->createMock(ApiEndpointDetector::class);
    $detector->method('isProtectedPath')->willReturn(TRUE);
    $detector->method('extractUsernameIdentifier')->willReturn('');

    $floodManager = $this->createMock(ApiFloodManager::class);
    $floodManager->expects($this->never())->method('clearUserFlood');

    $subscriber = $this->buildSubscriber(floodManager: $floodManager, detector: $detector);
    $event = $this->buildResponseEvent(
      Request::create('/user/login'),
      new Response('', 200),
    );

    $subscriber->onResponse($event);
  }

}
