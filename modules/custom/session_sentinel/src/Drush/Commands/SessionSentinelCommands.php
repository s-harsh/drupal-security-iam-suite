<?php

declare(strict_types=1);

namespace Drupal\session_sentinel\Drush\Commands;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\session_sentinel\Service\SessionSentinelManager;
use Drush\Attributes as CLI;
use Drush\Commands\DrushCommands;

/**
 * Drush commands for Session Sentinel.
 *
 * Commands:
 *   session-sentinel:prune  — Delete stale session metadata records.
 *   session-sentinel:list   — List all sessions for a given UID.
 *   session-sentinel:kill   — Kill a specific session by its ID hash.
 *   session-sentinel:status — Show a summary of active session counts.
 */
final class SessionSentinelCommands extends DrushCommands {

  public function __construct(
    private readonly SessionSentinelManager $manager,
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
  ) {
    parent::__construct();
  }

  /**
   * Prunes stale Session Sentinel metadata records.
   *
   * Removes records whose last_active timestamp is older than the configured
   * prune_age (default 7 days). Equivalent to the cron pruning job.
   */
  #[CLI\Command(name: 'session-sentinel:prune', aliases: ['ss:prune'])]
  #[CLI\Option(name: 'age', description: 'Override the prune age in seconds. Records older than this value are deleted.')]
  #[CLI\Usage(name: 'drush session-sentinel:prune', description: 'Prune stale session records using the configured prune age.')]
  #[CLI\Usage(name: 'drush session-sentinel:prune --age=86400', description: 'Prune records not active in the last 24 hours.')]
  public function prune(array $options = ['age' => NULL]): void {
    $config = $this->configFactory->get('session_sentinel.settings');
    $pruneAge = isset($options['age']) && is_numeric($options['age'])
      ? max(3600, (int) $options['age'])
      : max(3600, (int) ($config->get('prune_age') ?? 604800));

    $cutoff  = time() - $pruneAge;
    $deleted = (int) $this->database->delete('session_sentinel_sessions')
      ->condition('last_active', $cutoff, '<')
      ->execute();

    if ($deleted === 0) {
      $this->io()->note("No stale session records found (prune age: {$pruneAge}s).");
    }
    else {
      $this->io()->success("Pruned {$deleted} stale session record(s) older than {$pruneAge}s.");
    }
  }

  /**
   * Lists all active Session Sentinel records for a given user ID.
   *
   * @param int $uid The Drupal user ID to inspect.
   */
  #[CLI\Command(name: 'session-sentinel:list', aliases: ['ss:list'])]
  #[CLI\Argument(name: 'uid', description: 'The Drupal user ID whose sessions to list.')]
  #[CLI\Usage(name: 'drush session-sentinel:list 5', description: 'List all sessions for uid=5.')]
  public function listSessions(int $uid): void {
    if ($uid <= 0) {
      $this->io()->error('UID must be a positive integer.');
      return;
    }

    $sessions = $this->manager->getSessionsForUser($uid);

    if (empty($sessions)) {
      $this->io()->note("No session records found for uid={$uid}.");
      return;
    }

    $rows = [];
    $now  = time();

    foreach ($sessions as $record) {
      $rows[] = [
        $record->id,
        substr($record->sessionIdHash, 0, 16) . '...',
        $record->ipAddress,
        substr($record->userAgent, 0, 40) . (strlen($record->userAgent) > 40 ? '...' : ''),
        date('Y-m-d H:i:s', $record->lastActive),
        $record->idleSeconds($now) . 's',
        $record->flaggedDeviceChange ? 'YES' : 'No',
      ];
    }

    $this->io()->table(
      ['ID', 'Session Hash (prefix)', 'IP', 'User Agent', 'Last Active', 'Idle', 'Device Flagged'],
      $rows
    );
  }

  /**
   * Kills (invalidates) a specific session by its SHA-256 session ID hash.
   *
   * @param string $session_id_hash Full 64-character SHA-256 hash of the session ID.
   */
  #[CLI\Command(name: 'session-sentinel:kill', aliases: ['ss:kill'])]
  #[CLI\Argument(name: 'session_id_hash', description: 'The 64-character SHA-256 hash of the session ID to kill (shown in session-sentinel:list).')]
  #[CLI\Usage(name: 'drush session-sentinel:kill abc123...', description: 'Kill the session with the given SHA-256 hash.')]
  public function killSession(string $session_id_hash): void {
    $hash = trim($session_id_hash);

    if (strlen($hash) !== 64 || !ctype_xdigit($hash)) {
      $this->io()->error("'{$hash}' is not a valid 64-character hexadecimal SHA-256 hash.");
      return;
    }

    $record = $this->manager->loadRecord($hash);
    if ($record === NULL) {
      $this->io()->warning("No session record found for hash prefix " . substr($hash, 0, 12) . '... — it may have already been pruned.');
      return;
    }

    $this->manager->killSession($hash);
    $this->io()->success(
      "Killed session for uid={$record->uid} (hash prefix: " . substr($hash, 0, 12) . '...).'
    );
  }

  /**
   * Shows a summary of active Session Sentinel records.
   */
  #[CLI\Command(name: 'session-sentinel:status', aliases: ['ss:status'])]
  #[CLI\Usage(name: 'drush session-sentinel:status', description: 'Show active session counts and flagged anomaly count.')]
  public function status(): void {
    $config  = $this->configFactory->get('session_sentinel.settings');
    $pruneAge = max(3600, (int) ($config->get('prune_age') ?? 604800));
    $cutoff   = time() - $pruneAge;

    $total = (int) $this->database->select('session_sentinel_sessions', 's')
      ->condition('s.last_active', $cutoff, '>')
      ->countQuery()
      ->execute()
      ->fetchField();

    $flagged = (int) $this->database->select('session_sentinel_sessions', 's')
      ->condition('s.last_active', $cutoff, '>')
      ->condition('s.flagged_device_change', 1)
      ->countQuery()
      ->execute()
      ->fetchField();

    $stale = (int) $this->database->select('session_sentinel_sessions', 's')
      ->condition('s.last_active', $cutoff, '<')
      ->countQuery()
      ->execute()
      ->fetchField();

    $this->io()->table(
      ['Metric', 'Count'],
      [
        ['Active session records', $total],
        ['Flagged (device change)', $flagged],
        ['Stale records (pending prune)', $stale],
      ]
    );

    $this->io()->note([
      'Configured max concurrent sessions: ' . ($config->get('max_concurrent_sessions') ?? 3),
      'Global idle timeout: ' . ($config->get('idle_timeout') ?? 1800) . 's',
      'Device binding enabled: ' . ($config->get('enable_device_binding') ? 'yes' : 'no'),
    ]);
  }

}
