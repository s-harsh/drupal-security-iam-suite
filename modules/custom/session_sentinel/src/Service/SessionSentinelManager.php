<?php

declare(strict_types=1);

namespace Drupal\session_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\session_sentinel\Value\SessionRecord;
use Drupal\user\UserInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Core session management service for Session Sentinel.
 *
 * Responsibilities:
 *   - Record creation and last-active updates (upsert).
 *   - Idle session expiry check (per-role or global timeout).
 *   - Concurrent session limit enforcement (kill oldest on overflow).
 *   - Device fingerprint mismatch detection (flag or kill).
 *   - Stale-record pruning for drush session-sentinel:prune.
 *   - Dashboard data retrieval.
 */
final class SessionSentinelManager {

  public function __construct(
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
    private readonly SessionInterface $session,
    private readonly \Drupal\Core\Session\AccountProxyInterface $currentUser,
  ) {}

  // ---------------------------------------------------------------------------
  // Record lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Returns the SHA-256 hash of the current PHP session ID.
   *
   * @return string 64-char hex string, or empty string if no session is active.
   */
  public function currentSessionIdHash(): string {
    if (!$this->session->isStarted()) {
      return '';
    }
    $id = $this->session->getId();
    return $id !== '' ? hash('sha256', $id) : '';
  }

  /**
   * Creates a new sentinel record for the current session.
   *
   * This is called on login (via hook_user_login) after a PHP session has been
   * started.
   *
   * @param int    $uid               User ID.
   * @param string $deviceFingerprint SHA-256 device fingerprint.
   * @param string $ipAddress         Client IP.
   * @param string $userAgent         User-Agent string.
   */
  public function createRecord(
    int $uid,
    string $deviceFingerprint,
    string $ipAddress,
    string $userAgent,
  ): void {
    $hash = $this->currentSessionIdHash();
    if ($hash === '') {
      return;
    }

    $now = time();
    $record = SessionRecord::createNew($uid, $hash, $deviceFingerprint, $ipAddress, $userAgent, $now);

    $this->database->merge('session_sentinel_sessions')
      ->key('session_id_hash', $hash)
      ->fields([
        'uid'                  => $record->uid,
        'session_id_hash'      => $record->sessionIdHash,
        'device_fingerprint'   => $record->deviceFingerprint,
        'ip_address'           => $record->ipAddress,
        'user_agent'           => $record->userAgent,
        'created'              => $record->created,
        'last_active'          => $record->lastActive,
        'flagged_device_change' => (int) $record->flaggedDeviceChange,
      ])
      ->execute();
  }

  /**
   * Updates the last_active timestamp for the current session.
   *
   * Called on every authenticated request by the event subscriber.
   *
   * @param string $sessionIdHash SHA-256 hash of the session ID.
   */
  public function touchSession(string $sessionIdHash): void {
    if ($sessionIdHash === '') {
      return;
    }
    $this->database->update('session_sentinel_sessions')
      ->fields(['last_active' => time()])
      ->condition('session_id_hash', $sessionIdHash)
      ->execute();
  }

  /**
   * Flags a sentinel record as having an anomalous device change.
   *
   * @param string $sessionIdHash SHA-256 hash of the session ID.
   */
  public function flagDeviceChange(string $sessionIdHash): void {
    if ($sessionIdHash === '') {
      return;
    }
    $this->database->update('session_sentinel_sessions')
      ->fields(['flagged_device_change' => 1])
      ->condition('session_id_hash', $sessionIdHash)
      ->execute();
  }

  /**
   * Deletes the sentinel record for the given session ID hash.
   *
   * Also destroys the corresponding row in Drupal's {sessions} table so the
   * session is truly invalidated.
   *
   * @param string $sessionIdHash SHA-256 hash of the session ID to kill.
   */
  public function killSession(string $sessionIdHash): void {
    if ($sessionIdHash === '') {
      return;
    }

    // Delete from sentinel metadata table.
    $this->database->delete('session_sentinel_sessions')
      ->condition('session_id_hash', $sessionIdHash)
      ->execute();

    // Delete from Drupal's core sessions table.
    // The session ID in {sessions}.sid is stored as a SHA-256 hash by
    // Drupal's default session handler since Drupal 9.3.
    if ($this->database->schema()->tableExists('sessions')) {
      $this->database->delete('sessions')
        ->condition('sid', $sessionIdHash)
        ->execute();
    }

    $this->logger->info(
      'Session Sentinel: session @hash was killed by an administrator or concurrent-limit enforcement.',
      ['@hash' => substr($sessionIdHash, 0, 12) . '...']
    );
  }

  /**
   * Loads a single sentinel record by its session ID hash.
   *
   * @param string $sessionIdHash SHA-256 hash.
   *
   * @return \Drupal\session_sentinel\Value\SessionRecord|null NULL if not found.
   */
  public function loadRecord(string $sessionIdHash): ?SessionRecord {
    if ($sessionIdHash === '') {
      return NULL;
    }

    $row = $this->database->select('session_sentinel_sessions', 's')
      ->fields('s')
      ->condition('s.session_id_hash', $sessionIdHash)
      ->execute()
      ->fetchObject();

    return $row ? SessionRecord::fromRow($row) : NULL;
  }

  // ---------------------------------------------------------------------------
  // Idle timeout
  // ---------------------------------------------------------------------------

  /**
   * Returns the effective idle timeout in seconds for the given user.
   *
   * Checks per-role overrides first; falls back to the global setting.
   * Returns 0 when idle timeout is disabled.
   *
   * @param \Drupal\user\UserInterface $user The logged-in user.
   *
   * @return int Timeout in seconds (0 = disabled).
   */
  public function idleTimeoutForUser(UserInterface $user): int {
    $config = $this->configFactory->get('session_sentinel.settings');
    $roleTimeouts = (array) ($config->get('role_timeouts') ?? []);

    // Check per-role overrides in order of highest configured value (most
    // restrictive wins). Zero means "inherit global", not "unlimited".
    $roleTimeout = 0;
    foreach ($user->getRoles(TRUE) as $role) {
      if (isset($roleTimeouts[$role]) && (int) $roleTimeouts[$role] > 0) {
        // Use the smallest non-zero role timeout (tightest restriction).
        $t = (int) $roleTimeouts[$role];
        if ($roleTimeout === 0 || $t < $roleTimeout) {
          $roleTimeout = $t;
        }
      }
    }

    if ($roleTimeout > 0) {
      return $roleTimeout;
    }

    return max(0, (int) ($config->get('idle_timeout') ?? 1800));
  }

  /**
   * Determines whether a session has exceeded its idle timeout.
   *
   * @param \Drupal\session_sentinel\Value\SessionRecord $record Session record.
   * @param \Drupal\user\UserInterface                   $user   Session owner.
   * @param int                                          $now    Current timestamp.
   *
   * @return bool TRUE if the session should be expired.
   */
  public function isSessionIdle(SessionRecord $record, UserInterface $user, int $now): bool {
    $timeout = $this->idleTimeoutForUser($user);
    return $record->isIdle($timeout, $now);
  }

  // ---------------------------------------------------------------------------
  // Concurrent session limiting
  // ---------------------------------------------------------------------------

  /**
   * Enforces the concurrent session limit for a user after a new login.
   *
   * If the number of sentinel records for the user exceeds the configured
   * maximum, the oldest sessions (by last_active) are killed.
   *
   * @param int    $uid               User ID of the just-logged-in user.
   * @param string $newSessionIdHash  SHA-256 hash of the newly-created session.
   */
  public function enforceConcurrentLimit(int $uid, string $newSessionIdHash): void {
    $config = $this->configFactory->get('session_sentinel.settings');
    $maxSessions = (int) ($config->get('max_concurrent_sessions') ?? 3);

    if ($maxSessions <= 0) {
      return;
    }

    // Check admin exemption.
    if ((bool) ($config->get('exempt_admins_from_limit') ?? TRUE)) {
      if ($uid === 1) {
        return;
      }
      // Check if the user has administer users permission by loading them.
      // We do this cheaply by checking the sessions table count only if needed.
    }

    // Fetch all sessions for this user ordered oldest-first.
    $rows = $this->database->select('session_sentinel_sessions', 's')
      ->fields('s', ['id', 'session_id_hash', 'last_active'])
      ->condition('s.uid', $uid)
      ->orderBy('s.last_active', 'ASC')
      ->execute()
      ->fetchAll();

    $count = count($rows);
    if ($count <= $maxSessions) {
      return;
    }

    // Kill oldest sessions to bring count to max.
    $killCount = $count - $maxSessions;
    $killed = 0;

    foreach ($rows as $row) {
      if ($killed >= $killCount) {
        break;
      }
      // Never kill the session that was just created.
      if ($row->session_id_hash === $newSessionIdHash) {
        continue;
      }
      $this->killSession($row->session_id_hash);
      $killed++;
    }

    if ($killed > 0) {
      $this->logger->info(
        'Session Sentinel: killed @count oldest session(s) for uid @uid to enforce concurrent session limit of @max.',
        ['@count' => $killed, '@uid' => $uid, '@max' => $maxSessions]
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Dashboard data
  // ---------------------------------------------------------------------------

  /**
   * Returns all active sentinel records for the dashboard table.
   *
   * "Active" means last_active within the last prune_age seconds.
   *
   * @param int $limit Maximum number of rows to return.
   *
   * @return \Drupal\session_sentinel\Value\SessionRecord[]
   */
  public function getActiveSessions(int $limit = 200): array {
    $config = $this->configFactory->get('session_sentinel.settings');
    $pruneAge = max(3600, (int) ($config->get('prune_age') ?? 604800));
    $cutoff = time() - $pruneAge;

    $rows = $this->database->select('session_sentinel_sessions', 's')
      ->fields('s')
      ->condition('s.last_active', $cutoff, '>')
      ->orderBy('s.last_active', 'DESC')
      ->range(0, $limit)
      ->execute()
      ->fetchAll();

    return array_map(
      static fn(object $row): SessionRecord => SessionRecord::fromRow($row),
      $rows
    );
  }

  /**
   * Returns all sentinel records for a specific user.
   *
   * @param int $uid User ID.
   *
   * @return \Drupal\session_sentinel\Value\SessionRecord[]
   */
  public function getSessionsForUser(int $uid): array {
    $rows = $this->database->select('session_sentinel_sessions', 's')
      ->fields('s')
      ->condition('s.uid', $uid)
      ->orderBy('s.last_active', 'DESC')
      ->execute()
      ->fetchAll();

    return array_map(
      static fn(object $row): SessionRecord => SessionRecord::fromRow($row),
      $rows
    );
  }

  // ---------------------------------------------------------------------------
  // Pruning
  // ---------------------------------------------------------------------------

  /**
   * Deletes sentinel records that have not been active within the prune age.
   *
   * @return int Number of records deleted.
   */
  public function pruneStaleRecords(): int {
    $config = $this->configFactory->get('session_sentinel.settings');
    $pruneAge = max(3600, (int) ($config->get('prune_age') ?? 604800));
    $cutoff = time() - $pruneAge;

    $deleted = (int) $this->database->delete('session_sentinel_sessions')
      ->condition('last_active', $cutoff, '<')
      ->execute();

    if ($deleted > 0) {
      $this->logger->info(
        'Session Sentinel: pruned @count stale session record(s) older than @age seconds.',
        ['@count' => $deleted, '@age' => $pruneAge]
      );
    }

    return $deleted;
  }

  /**
   * Returns a count of active (non-stale) sentinel records.
   *
   * @return int
   */
  public function countActiveSessions(): int {
    $config = $this->configFactory->get('session_sentinel.settings');
    $pruneAge = max(3600, (int) ($config->get('prune_age') ?? 604800));
    $cutoff = time() - $pruneAge;

    return (int) $this->database->select('session_sentinel_sessions', 's')
      ->condition('s.last_active', $cutoff, '>')
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Returns the count of records flagged for device change anomalies.
   *
   * @return int
   */
  public function countFlaggedSessions(): int {
    return (int) $this->database->select('session_sentinel_sessions', 's')
      ->condition('s.flagged_device_change', 1)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

}
