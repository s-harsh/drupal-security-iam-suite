<?php

declare(strict_types=1);

namespace Drupal\session_sentinel\Controller;

use Drupal\Component\Utility\Html;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Database\Connection;
use Drupal\Core\Url;
use Drupal\session_sentinel\Service\SessionSentinelManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller for the Session Sentinel admin dashboard.
 *
 * Provides:
 *   - dashboardPage(): HTML table of all active sessions with Kill buttons.
 *   - killSession():   CSRF-protected action to kill a session by hash.
 *   - dashboardData(): JSON endpoint for JavaScript-driven auto-refresh.
 */
final class SessionDashboardController extends ControllerBase {

  public function __construct(
    private readonly SessionSentinelManager $manager,
    private readonly Connection $database,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('session_sentinel.manager'),
      $container->get('database'),
    );
  }

  /**
   * Renders the admin dashboard with a live table of active sessions.
   *
   * @return array Render array.
   */
  public function dashboardPage(): array {
    $sessions = $this->manager->getActiveSessions(300);
    $now = time();

    // Load username map for the UIDs present.
    $uids = array_unique(array_map(static fn($r) => $r->uid, $sessions));
    $usernames = [];
    if (!empty($uids)) {
      $rows = $this->database->select('users_field_data', 'u')
        ->fields('u', ['uid', 'name'])
        ->condition('u.uid', $uids, 'IN')
        ->execute()
        ->fetchAllKeyed(0, 1);
      $usernames = $rows;
    }

    $rows = [];
    foreach ($sessions as $record) {
      $idleSeconds = $record->idleSeconds($now);
      $idleLabel = $this->formatIdle($idleSeconds);

      $username = $usernames[$record->uid] ?? $this->t('uid @uid', ['@uid' => $record->uid]);

      $flaggedCell = $record->flaggedDeviceChange
        ? '<span style="color:#c62828;font-weight:bold;">' . $this->t('YES') . '</span>'
        : $this->t('No');

      $killUrl = Url::fromRoute('session_sentinel.kill', ['session_id' => $record->sessionIdHash], [
        'query' => ['token' => \Drupal::csrfToken()->get('session_sentinel_kill_' . $record->sessionIdHash)],
      ])->toString();

      $killLink = '<a href="' . Html::escape($killUrl) . '" class="button button--danger button--small" '
        . 'onclick="return confirm(\'' . $this->t('Kill this session?') . '\')">'
        . $this->t('Kill') . '</a>';

      $rows[] = [
        Html::escape($username),
        $record->uid,
        Html::escape($record->ipAddress),
        Html::escape(substr($record->userAgent, 0, 60) . (strlen($record->userAgent) > 60 ? '...' : '')),
        $idleLabel,
        date('Y-m-d H:i:s', $record->lastActive),
        ['data' => ['#markup' => $flaggedCell]],
        ['data' => ['#markup' => $killLink]],
      ];
    }

    $build = [];

    $build['summary'] = [
      '#markup' => '<p>' . $this->t(
        'Total active sessions: <strong>@total</strong> &nbsp;|&nbsp; Flagged: <strong>@flagged</strong>',
        [
          '@total'   => count($sessions),
          '@flagged' => count(array_filter($sessions, static fn($r) => $r->flaggedDeviceChange)),
        ]
      ) . '</p>',
    ];

    $build['table'] = [
      '#type'    => 'table',
      '#header'  => [
        $this->t('User'),
        $this->t('UID'),
        $this->t('IP Address'),
        $this->t('User Agent'),
        $this->t('Idle'),
        $this->t('Last Active'),
        $this->t('Device Flagged'),
        $this->t('Actions'),
      ],
      '#rows'    => $rows,
      '#empty'   => $this->t('No active sessions found.'),
      '#attributes' => ['data-session-sentinel-table' => TRUE],
    ];

    $build['refresh_status'] = [
      '#markup' => '<p data-session-sentinel-status></p>',
    ];

    // Attach auto-refresh settings.
    $build['#attached']['drupalSettings']['sessionSentinelDashboard'] = [
      'dataUrl'      => Url::fromRoute('session_sentinel.dashboard_data')->toString(),
      'pollInterval' => 15000,
    ];

    return $build;
  }

  /**
   * CSRF-protected action to kill a session by its session ID hash.
   *
   * @param string  $session_id Session ID hash (from route parameter).
   * @param Request $request    Current request.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   */
  public function killSession(string $session_id, Request $request): RedirectResponse {
    $token = $request->query->get('token', '');
    if (!$token || !\Drupal::csrfToken()->validate((string) $token, 'session_sentinel_kill_' . $session_id)) {
      $this->messenger()->addError($this->t('Invalid CSRF token. Action not performed.'));
      return new RedirectResponse(Url::fromRoute('session_sentinel.dashboard')->toString());
    }

    if ($session_id === '') {
      $this->messenger()->addError($this->t('Invalid session ID.'));
      return new RedirectResponse(Url::fromRoute('session_sentinel.dashboard')->toString());
    }

    $this->manager->killSession($session_id);
    $this->messenger()->addStatus($this->t('Session killed successfully.'));

    return new RedirectResponse(Url::fromRoute('session_sentinel.dashboard')->toString());
  }

  /**
   * Returns current session data as JSON for the auto-refresh endpoint.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   */
  public function dashboardData(): JsonResponse {
    $sessions = $this->manager->getActiveSessions(300);
    $now = time();

    // Load usernames.
    $uids = array_unique(array_map(static fn($r) => $r->uid, $sessions));
    $usernames = [];
    if (!empty($uids)) {
      $rows = $this->database->select('users_field_data', 'u')
        ->fields('u', ['uid', 'name'])
        ->condition('u.uid', $uids, 'IN')
        ->execute()
        ->fetchAllKeyed(0, 1);
      $usernames = $rows;
    }

    $data = [];
    foreach ($sessions as $record) {
      $idleSeconds = $record->idleSeconds($now);
      $data[] = [
        'id'                   => $record->id,
        'uid'                  => $record->uid,
        'username'             => $usernames[$record->uid] ?? 'uid:' . $record->uid,
        'ip_address'           => $record->ipAddress,
        'user_agent'           => substr($record->userAgent, 0, 80),
        'idle_seconds'         => $idleSeconds,
        'idle_label'           => $this->formatIdle($idleSeconds),
        'last_active'          => date('Y-m-d H:i:s', $record->lastActive),
        'flagged_device_change' => $record->flaggedDeviceChange,
        'session_id_hash'      => $record->sessionIdHash,
      ];
    }

    return new JsonResponse([
      'sessions'  => $data,
      'timestamp' => $now,
      'total'     => count($data),
      'flagged'   => count(array_filter($sessions, static fn($r) => $r->flaggedDeviceChange)),
    ]);
  }

  /**
   * Formats an idle duration in seconds as a human-readable string.
   *
   * @param int $seconds Idle time in seconds.
   *
   * @return string E.g. "2m 15s", "1h 5m".
   */
  private function formatIdle(int $seconds): string {
    if ($seconds < 60) {
      return $seconds . 's';
    }
    if ($seconds < 3600) {
      $m = intdiv($seconds, 60);
      $s = $seconds % 60;
      return $m . 'm ' . $s . 's';
    }
    $h = intdiv($seconds, 3600);
    $m = intdiv($seconds % 3600, 60);
    return $h . 'h ' . $m . 'm';
  }

}
