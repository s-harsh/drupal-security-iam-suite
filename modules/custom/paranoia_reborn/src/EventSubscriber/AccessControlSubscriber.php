<?php

declare(strict_types=1);

namespace Drupal\paranoia_reborn\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\paranoia_reborn\Service\PathRestrictor;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Intercepts incoming requests and enforces Paranoia Reborn access rules.
 *
 * Subscribes to KernelEvents::REQUEST at priority 33 — after Drupal's router
 * has matched the request (priority 40) but before the controller fires.
 * Returns a plain 403 response for blocked paths and, when audit logging is
 * enabled, writes a structured watchdog entry via the logger channel.
 *
 * Sub-requests (e.g. ESI fragments) are skipped intentionally: they are always
 * internal and the outer request has already been checked.
 */
final class AccessControlSubscriber implements EventSubscriberInterface {

  /**
   * Constructs an AccessControlSubscriber.
   *
   * @param \Drupal\paranoia_reborn\Service\PathRestrictor $pathRestrictor
   *   The path restriction service.
   * @param \Drupal\Core\Session\AccountInterface $currentUser
   *   The currently authenticated account.
   * @param \Psr\Log\LoggerInterface $logger
   *   The paranoia_reborn logger channel.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory (used to read audit_log_enabled).
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack (used for IP logging).
   */
  public function __construct(
    private readonly PathRestrictor $pathRestrictor,
    private readonly AccountInterface $currentUser,
    private readonly LoggerInterface $logger,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly RequestStack $requestStack,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      KernelEvents::REQUEST => ['onRequest', 33],
    ];
  }

  /**
   * Checks the incoming request path against Paranoia Reborn rules.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The kernel request event.
   */
  public function onRequest(RequestEvent $event): void {
    // Only check the main request — skip ESI sub-requests.
    if (!$event->isMainRequest()) {
      return;
    }

    $request = $event->getRequest();
    $path    = $request->getPathInfo();

    if (!$this->pathRestrictor->isBlocked($path, $this->currentUser)) {
      return;
    }

    // Build 403 response before logging so we can include the status.
    $response = new Response(
      content: 'Access denied.',
      status: Response::HTTP_FORBIDDEN,
    );

    $this->auditLog($path);

    $event->setResponse($response);
  }

  /**
   * Writes a structured audit log entry for a blocked access attempt.
   *
   * @param string $path
   *   The blocked request path.
   */
  private function auditLog(string $path): void {
    $config = $this->configFactory->get('paranoia_reborn.settings');

    if (!(bool) ($config->get('audit_log_enabled') ?? TRUE)) {
      return;
    }

    $request = $this->requestStack->getCurrentRequest();
    $ip      = $request?->getClientIp() ?? 'unknown';
    $reason  = $this->pathRestrictor->blockReason($path, $this->currentUser);

    $this->logger->warning(
      'Paranoia Reborn blocked access to @path for uid @uid (roles: @roles) from IP @ip. Reason: @reason.',
      [
        '@path'   => $path,
        '@uid'    => $this->currentUser->id(),
        '@roles'  => implode(', ', $this->currentUser->getRoles()),
        '@ip'     => $ip,
        '@reason' => $reason,
      ]
    );
  }

}
