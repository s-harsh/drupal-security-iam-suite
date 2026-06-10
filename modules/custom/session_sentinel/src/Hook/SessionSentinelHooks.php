<?php

declare(strict_types=1);

namespace Drupal\session_sentinel\Hook;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\Link;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\session_sentinel\Service\SessionSentinelManager;
use Drupal\user\UserInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * OOP hook implementations for Session Sentinel.
 *
 * Registered in session_sentinel.services.yml with the drupal.hook tag.
 */
final class SessionSentinelHooks {

  use StringTranslationTrait;

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
    private readonly SessionSentinelManager $manager,
  ) {}

  /**
   * Implements hook_help().
   */
  #[Hook('help')]
  public function help(string $route_name, RouteMatchInterface $route_match): string|array {
    if ($route_name !== 'help.page.session_sentinel') {
      return [];
    }

    $settingsUrl  = Url::fromRoute('session_sentinel.settings');
    $dashboardUrl = Url::fromRoute('session_sentinel.dashboard');

    $settingsLink  = Link::fromTextAndUrl($this->t('Session Sentinel Settings'), $settingsUrl)->toString();
    $dashboardLink = Link::fromTextAndUrl($this->t('Active Sessions Dashboard'), $dashboardUrl)->toString();

    $output  = '<h2>' . $this->t('About') . '</h2>';
    $output .= '<p>' . $this->t('Session Sentinel combines idle session timeout, concurrent session limiting, and device fingerprint binding into a single module. It replaces the unmaintained session_limit, session_expire, and user_protect modules.') . '</p>';
    $output .= '<h2>' . $this->t('Features') . '</h2>';
    $output .= '<ul>';
    $output .= '<li>' . $this->t('<strong>Idle timeout</strong>: configurable globally and per-role. A JavaScript countdown banner warns users before their session expires.') . '</li>';
    $output .= '<li>' . $this->t('<strong>Concurrent session limit</strong>: limits users to N simultaneous sessions. The oldest session is killed automatically when the limit is exceeded.') . '</li>';
    $output .= '<li>' . $this->t('<strong>Device fingerprint binding</strong>: anomalous mid-session device changes are flagged and optionally used to immediately terminate the session.') . '</li>';
    $output .= '<li>' . $this->t('<strong>Admin dashboard</strong>: lists all active sessions with kill buttons.') . '</li>';
    $output .= '</ul>';
    $output .= '<h2>' . $this->t('Administration') . '</h2>';
    $output .= '<ul>';
    $output .= '<li>' . $this->t('@link — Configure timeouts, limits, and device binding.', ['@link' => $settingsLink]) . '</li>';
    $output .= '<li>' . $this->t('@link — View and kill active sessions in real time.', ['@link' => $dashboardLink]) . '</li>';
    $output .= '</ul>';

    return ['#markup' => $output];
  }

  /**
   * Implements hook_user_login().
   *
   * Creates the sentinel record for the new session and enforces the
   * concurrent session limit.
   */
  #[Hook('user_login')]
  public function userLogin(UserInterface $account): void {
    $request = \Drupal::request();
    $fingerprint = \Drupal::service('session_sentinel.device_fingerprint');

    $deviceFp  = $fingerprint->generate($request);
    $ipAddress = (string) ($request->getClientIp() ?? '');
    $userAgent = (string) ($request->headers->get('User-Agent') ?? '');

    $uid = (int) $account->id();

    // Create the sentinel record for this session.
    $this->manager->createRecord($uid, $deviceFp, $ipAddress, $userAgent);

    $hash = $this->manager->currentSessionIdHash();

    // Enforce concurrent session limit.
    $this->manager->enforceConcurrentLimit($uid, $hash);

    $this->logger->info(
      'Session Sentinel: new session recorded for uid @uid from @ip.',
      ['@uid' => $uid, '@ip' => $ipAddress]
    );
  }

  /**
   * Implements hook_user_logout().
   *
   * Cleans up the sentinel record when the user explicitly logs out.
   */
  #[Hook('user_logout')]
  public function userLogout(UserInterface $account): void {
    $hash = $this->manager->currentSessionIdHash();
    if ($hash !== '') {
      $this->manager->killSession($hash);
    }
  }

  /**
   * Implements hook_cron().
   *
   * Prunes stale sentinel records and logs a summary.
   */
  #[Hook('cron')]
  public function cron(): void {
    $pruned  = $this->manager->pruneStaleRecords();
    $active  = $this->manager->countActiveSessions();
    $flagged = $this->manager->countFlaggedSessions();

    $this->logger->info(
      'Session Sentinel cron: @pruned stale record(s) pruned, @active active session(s), @flagged flagged for device change.',
      ['@pruned' => $pruned, '@active' => $active, '@flagged' => $flagged]
    );
  }

  /**
   * Implements hook_page_attachments().
   *
   * Attaches the session timeout warning library and drupalSettings to
   * authenticated HTML page responses.
   */
  #[Hook('page_attachments')]
  public function pageAttachments(array &$attachments): void {
    $currentUser = \Drupal::currentUser();
    if ($currentUser->isAnonymous()) {
      return;
    }

    $config     = $this->configFactory->get('session_sentinel.settings');
    $idleTimeout = max(0, (int) ($config->get('idle_timeout') ?? 1800));

    if ($idleTimeout <= 0) {
      return;
    }

    $warningLeadTime = max(60, (int) ($config->get('warning_lead_time') ?? 300));

    $attachments['#attached']['library'][] = 'session_sentinel/session_timeout_warning';
    $attachments['#attached']['drupalSettings']['sessionSentinel'] = [
      'idleTimeout'     => $idleTimeout,
      'warningLeadTime' => $warningLeadTime,
      'keepAliveUrl'    => Url::fromRoute('user.login')->toString(),
      'logoutUrl'       => Url::fromRoute('user.logout')->toString(),
    ];
  }

}
