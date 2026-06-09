<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\EventSubscriber;

use Drupal\api_flood_guard\Service\ApiEndpointDetector;
use Drupal\api_flood_guard\Service\ApiFloodManager;
use Drupal\Component\Utility\Html;
use Drupal\Core\Config\ConfigFactoryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Kernel event subscriber that enforces API flood protection.
 *
 * Subscribes to KernelEvents::REQUEST at priority 300 (before routing,
 * authentication, and page cache) and KernelEvents::RESPONSE at priority -100
 * (after the final response is built, to clear flood counters on success).
 */
final class ApiFloodSubscriber implements EventSubscriberInterface {

  public function __construct(
    private readonly ApiFloodManager $floodManager,
    private readonly ApiEndpointDetector $endpointDetector,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      KernelEvents::REQUEST  => [['onRequest', 300]],
      KernelEvents::RESPONSE => [['onResponse', -100]],
    ];
  }

  /**
   * Evaluates incoming requests and blocks those exceeding flood thresholds.
   *
   * Only processes sub-requests if they match the master request to avoid
   * interfering with internal Drupal subrequests.
   */
  public function onRequest(RequestEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }

    $request = $event->getRequest();

    // Stage 1: Only act on protected API paths.
    if (!$this->endpointDetector->isProtectedPath($request)) {
      return;
    }

    // Stage 2: Skip HTML form submissions (handled by Drupal core form flood).
    if ($this->endpointDetector->isHtmlFormSubmission($request)) {
      return;
    }

    $clientIp = (string) $request->getClientIp();
    $usernameHash = $this->endpointDetector->extractUsernameIdentifier($request);

    $decision = $this->floodManager->evaluate($request, $clientIp, $usernameHash);

    if ($decision->allowed) {
      return;
    }

    // Build and set the block response.
    $response = $this->buildBlockResponse($request, $decision->retryAfter);
    $event->setResponse($response);
  }

  /**
   * Clears per-username flood counters on successful authentication responses.
   */
  public function onResponse(ResponseEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }

    $request = $event->getRequest();

    if (!$this->endpointDetector->isProtectedPath($request)) {
      return;
    }

    if ($event->getResponse()->getStatusCode() !== 200) {
      return;
    }

    $usernameHash = $this->endpointDetector->extractUsernameIdentifier($request);
    if ($usernameHash !== '') {
      $this->floodManager->clearUserFlood($usernameHash);
    }
  }

  /**
   * Builds the HTTP response for a blocked request.
   *
   * Returns a JSON:API-compatible JSON response if the request's Accept header
   * includes application/json or application/vnd.api+json; otherwise returns
   * a plain-text response.
   */
  private function buildBlockResponse(
    \Symfony\Component\HttpFoundation\Request $request,
    int $retryAfter,
  ): Response {
    $config = $this->configFactory->get('api_flood_guard.settings');
    $statusCode = (int) ($config->get('response_code') ?? 429);
    $message = (string) ($config->get('block_message') ?? 'Too many authentication requests. Please wait before trying again.');

    $accept = $request->headers->get('Accept', '');
    $wantsJson = str_contains($accept, 'application/json') || str_contains($accept, 'application/vnd.api+json');

    $headers = [
      'Retry-After' => (string) max(0, $retryAfter),
      'Cache-Control' => 'no-store, no-cache',
      'X-Content-Type-Options' => 'nosniff',
    ];

    if ($wantsJson) {
      $body = [
        'errors' => [
          [
            'status' => (string) $statusCode,
            'title'  => $statusCode === 429 ? 'Too Many Requests' : 'Service Unavailable',
            'detail' => Html::escape($message),
          ],
        ],
      ];
      return new JsonResponse($body, $statusCode, $headers);
    }

    return new Response(
      Html::escape($message),
      $statusCode,
      array_merge($headers, ['Content-Type' => 'text/plain; charset=UTF-8']),
    );
  }

}
