<?php

declare(strict_types=1);

namespace Drupal\session_sentinel\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\session_sentinel\Service\DeviceFingerprintService;
use Drupal\session_sentinel\Service\SessionSentinelManager;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Kernel request subscriber that enforces idle timeout and device binding.
 *
 * On every authenticated request:
 *   1. Loads the sentinel record for the current session.
 *   2. Checks whether the session has exceeded its idle timeout; if so,
 *      destroys it and redirects to the login page.
 *   3. Checks the device fingerprint against the stored record; if it has
 *      changed, flags (or kills) the session based on configuration.
 *   4. Touches (updates) the last_active timestamp.
 *   5. On page responses to authenticated users, attaches the JS countdown
 *      library with the appropriate drupalSettings.
 */
final class SessionTimeoutSubscriber implements EventSubscriberInterface {

  use StringTranslationTrait;

  public function __construct(
    private readonly SessionSentinelManager $manager,
    private readonly DeviceFingerprintService $fingerprint,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly AccountProxyInterface $currentUser,
    private readonly LoggerInterface $logger,
    private readonly MessengerInterface $messenger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      KernelEvents::REQUEST  => [['onRequest', 30]],
      KernelEvents::RESPONSE => [['onResponse', -20]],
    ];
  }

  /**
   * Enforces idle timeout and device fingerprint checks on each request.
   */
  public function onRequest(RequestEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }

    $request = $event->getRequest();

    // Only act on authenticated (non-anonymous) users.
    if ($this->currentUser->isAnonymous()) {
      return;
    }

    // Skip Drush / CLI requests.
    if (PHP_SAPI === 'cli') {
      return;
    }

    $hash = $this->manager->currentSessionIdHash();
    if ($hash === '') {
      return;
    }

    $record = $this->manager->loadRecord($hash);

    if ($record === NULL) {
      // No sentinel record — could be a pre-existing session before module
      // install. Do not interfere, but skip further checks.
      return;
    }

    $now = time();

    // --- Idle timeout check ---
    $config = $this->configFactory->get('session_sentinel.settings');
    $idleTimeout = max(0, (int) ($config->get('idle_timeout') ?? 1800));

    // Per-role timeout override.
    $idleTimeout = $this->resolveRoleTimeout($idleTimeout);

    if ($idleTimeout > 0 && $record->isIdle($idleTimeout, $now)) {
      $this->logger->info(
        'Session Sentinel: session for uid @uid expired after @idle seconds of inactivity.',
        ['@uid' => $record->uid, '@idle' => $record->idleSeconds($now)]
      );

      $this->manager->killSession($hash);
      $this->currentUser->getAccount(); // Refresh account.

      $this->messenger->addWarning(
        $this->t('Your session expired due to inactivity. Please log in again.')
      );

      $loginUrl = \Drupal\Core\Url::fromRoute('user.login')->toString();
      $event->setResponse(new RedirectResponse($loginUrl));
      return;
    }

    // --- Device fingerprint check ---
    if ($this->fingerprint->isEnabled()) {
      $currentFingerprint = $this->fingerprint->generate($request);

      if (!$this->fingerprint->matches($record->deviceFingerprint, $currentFingerprint)) {
        $this->logger->warning(
          'Session Sentinel: device fingerprint mismatch for uid @uid session @hash. Stored: @stored, Current: @current. IP: @ip.',
          [
            '@uid'     => $record->uid,
            '@hash'    => substr($hash, 0, 12) . '...',
            '@stored'  => substr($record->deviceFingerprint, 0, 12) . '...',
            '@current' => substr($currentFingerprint, 0, 12) . '...',
            '@ip'      => $request->getClientIp(),
          ]
        );

        if ($this->fingerprint->killOnChange()) {
          $this->manager->killSession($hash);
          $this->messenger->addWarning(
            $this->t('Your session was terminated because your device information changed unexpectedly.')
          );
          $loginUrl = \Drupal\Core\Url::fromRoute('user.login')->toString();
          $event->setResponse(new RedirectResponse($loginUrl));
          return;
        }

        // Flag the record without killing it.
        $this->manager->flagDeviceChange($hash);
      }
    }

    // --- Touch last-active timestamp ---
    $this->manager->touchSession($hash);
  }

  /**
   * Attaches the JS countdown library and drupalSettings on HTML responses.
   *
   * Only fires for authenticated users on main HTML page responses.
   */
  public function onResponse(ResponseEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }

    if ($this->currentUser->isAnonymous()) {
      return;
    }

    $response = $event->getResponse();

    // Only attach to HTML responses (not JSON/redirect/etc.).
    if (!($response instanceof \Symfony\Component\HttpFoundation\Response)) {
      return;
    }

    $contentType = $response->headers->get('Content-Type', '');
    if (!str_contains($contentType, 'text/html') && $contentType !== '') {
      return;
    }

    // Lazy check: only add to HtmlResponse to avoid polluting non-Drupal pages.
    if (!($response instanceof \Drupal\Core\Render\HtmlResponse)) {
      return;
    }

    $config = $this->configFactory->get('session_sentinel.settings');
    $idleTimeout = max(0, (int) ($config->get('idle_timeout') ?? 1800));
    $idleTimeout = $this->resolveRoleTimeout($idleTimeout);

    if ($idleTimeout <= 0) {
      return;
    }

    $warningLeadTime = max(60, (int) ($config->get('warning_lead_time') ?? 300));

    // Attach settings; the library is added via hook_page_attachments in Hooks.
    // We set drupalSettings here so they are available before JS executes.
    $attachments = [
      'library' => ['session_sentinel/session_timeout_warning'],
      'drupalSettings' => [
        'sessionSentinel' => [
          'idleTimeout'      => $idleTimeout,
          'warningLeadTime'  => $warningLeadTime,
          'keepAliveUrl'     => \Drupal\Core\Url::fromRoute('user.login')->toString(),
          'logoutUrl'        => \Drupal\Core\Url::fromRoute('user.logout')->toString(),
        ],
      ],
    ];

    // Merge attachments into the response's attached metadata.
    $existing = $response->getAttachments();
    $existing['library'] = array_unique(array_merge($existing['library'] ?? [], $attachments['library']));
    $existing['drupalSettings']['sessionSentinel'] = $attachments['drupalSettings']['sessionSentinel'];
    $response->setAttachments($existing);
  }

  /**
   * Resolves the effective idle timeout applying per-role overrides.
   *
   * @param int $globalTimeout The globally configured timeout in seconds.
   *
   * @return int Effective timeout (0 = disabled).
   */
  private function resolveRoleTimeout(int $globalTimeout): int {
    $config = $this->configFactory->get('session_sentinel.settings');
    $roleTimeouts = (array) ($config->get('role_timeouts') ?? []);

    if (empty($roleTimeouts)) {
      return $globalTimeout;
    }

    $roles = $this->currentUser->getRoles(TRUE);
    $best = 0;

    foreach ($roles as $role) {
      if (isset($roleTimeouts[$role]) && (int) $roleTimeouts[$role] > 0) {
        $t = (int) $roleTimeouts[$role];
        if ($best === 0 || $t < $best) {
          $best = $t;
        }
      }
    }

    return $best > 0 ? $best : $globalTimeout;
  }

}
