<?php

declare(strict_types=1);

namespace Drupal\session_sentinel\Value;

/**
 * Immutable value object representing a single session metadata record.
 *
 * Populated from the session_sentinel_sessions database table or from
 * live request data before the record is persisted.
 */
final readonly class SessionRecord {

  /**
   * Constructs a SessionRecord.
   *
   * @param int    $id                   Auto-increment primary key (0 for unsaved records).
   * @param int    $uid                  Drupal user ID.
   * @param string $sessionIdHash        SHA-256 hash of the PHP session ID.
   * @param string $deviceFingerprint    SHA-256 device fingerprint.
   * @param string $ipAddress            Client IP address.
   * @param string $userAgent            User-Agent string (max 512 chars).
   * @param int    $created              Unix timestamp of record creation.
   * @param int    $lastActive           Unix timestamp of last recorded activity.
   * @param bool   $flaggedDeviceChange  Whether an anomalous device change was detected.
   */
  public function __construct(
    public readonly int $id,
    public readonly int $uid,
    public readonly string $sessionIdHash,
    public readonly string $deviceFingerprint,
    public readonly string $ipAddress,
    public readonly string $userAgent,
    public readonly int $created,
    public readonly int $lastActive,
    public readonly bool $flaggedDeviceChange,
  ) {}

  /**
   * Creates a new SessionRecord for an incoming request (not yet persisted).
   *
   * @param int    $uid               Drupal user ID.
   * @param string $sessionIdHash     SHA-256 hash of the current PHP session ID.
   * @param string $deviceFingerprint SHA-256 device fingerprint for this request.
   * @param string $ipAddress         Client IP address.
   * @param string $userAgent         User-Agent string.
   * @param int    $now               Current Unix timestamp.
   *
   * @return self
   */
  public static function createNew(
    int $uid,
    string $sessionIdHash,
    string $deviceFingerprint,
    string $ipAddress,
    string $userAgent,
    int $now,
  ): self {
    return new self(
      id: 0,
      uid: $uid,
      sessionIdHash: $sessionIdHash,
      deviceFingerprint: $deviceFingerprint,
      ipAddress: $ipAddress,
      userAgent: substr($userAgent, 0, 512),
      created: $now,
      lastActive: $now,
      flaggedDeviceChange: FALSE,
    );
  }

  /**
   * Creates a SessionRecord from a raw database row (stdClass or array).
   *
   * @param object|array $row Database result row.
   *
   * @return self
   */
  public static function fromRow(object|array $row): self {
    if (is_array($row)) {
      $row = (object) $row;
    }

    return new self(
      id: (int) $row->id,
      uid: (int) $row->uid,
      sessionIdHash: (string) $row->session_id_hash,
      deviceFingerprint: (string) $row->device_fingerprint,
      ipAddress: (string) $row->ip_address,
      userAgent: (string) $row->user_agent,
      created: (int) $row->created,
      lastActive: (int) $row->last_active,
      flaggedDeviceChange: (bool) $row->flagged_device_change,
    );
  }

  /**
   * Returns a copy of this record with an updated last_active timestamp.
   *
   * @param int $timestamp New last-active Unix timestamp.
   *
   * @return self
   */
  public function withLastActive(int $timestamp): self {
    return new self(
      id: $this->id,
      uid: $this->uid,
      sessionIdHash: $this->sessionIdHash,
      deviceFingerprint: $this->deviceFingerprint,
      ipAddress: $this->ipAddress,
      userAgent: $this->userAgent,
      created: $this->created,
      lastActive: $timestamp,
      flaggedDeviceChange: $this->flaggedDeviceChange,
    );
  }

  /**
   * Returns a copy of this record with the device-change flag set.
   *
   * @return self
   */
  public function withDeviceFlagged(): self {
    return new self(
      id: $this->id,
      uid: $this->uid,
      sessionIdHash: $this->sessionIdHash,
      deviceFingerprint: $this->deviceFingerprint,
      ipAddress: $this->ipAddress,
      userAgent: $this->userAgent,
      created: $this->created,
      lastActive: $this->lastActive,
      flaggedDeviceChange: TRUE,
    );
  }

  /**
   * Returns how many seconds the session has been idle.
   *
   * @param int $now Current Unix timestamp.
   *
   * @return int Idle seconds (always >= 0).
   */
  public function idleSeconds(int $now): int {
    return max(0, $now - $this->lastActive);
  }

  /**
   * Whether this session has been idle longer than the given timeout.
   *
   * @param int $timeoutSeconds Idle timeout in seconds.
   * @param int $now            Current Unix timestamp.
   *
   * @return bool
   */
  public function isIdle(int $timeoutSeconds, int $now): bool {
    if ($timeoutSeconds <= 0) {
      return FALSE;
    }
    return $this->idleSeconds($now) >= $timeoutSeconds;
  }

}
