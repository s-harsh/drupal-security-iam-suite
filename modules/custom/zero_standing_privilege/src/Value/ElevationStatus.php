<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Value;

/**
 * Enumeration of possible states for an ElevationRequest entity.
 *
 * Using a backed enum (PHP 8.1+) so values are serialisable to the DB column
 * and can be compared without string literals scattered through business logic.
 */
enum ElevationStatus: string {

  /**
   * Request submitted, awaiting approver action.
   */
  case Pending = 'pending';

  /**
   * Approved by an approver; the target role is currently active.
   */
  case Approved = 'approved';

  /**
   * Denied by an approver; no role was granted.
   */
  case Denied = 'denied';

  /**
   * Grant reached its scheduled expiry time; role has been revoked.
   */
  case Expired = 'expired';

  /**
   * Manually revoked before expiry by the user or an administrator.
   */
  case Revoked = 'revoked';

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Returns a human-readable label for display in admin UIs.
   */
  public function label(): string {
    return match($this) {
      self::Pending  => 'Pending',
      self::Approved => 'Approved',
      self::Denied   => 'Denied',
      self::Expired  => 'Expired',
      self::Revoked  => 'Revoked',
    };
  }

  /**
   * Returns true if the elevation is currently active (role is live).
   */
  public function isActive(): bool {
    return $this === self::Approved;
  }

  /**
   * Returns true if the request is in a terminal state (no further transitions).
   */
  public function isTerminal(): bool {
    return match($this) {
      self::Denied, self::Expired, self::Revoked => true,
      default => false,
    };
  }

  /**
   * Returns true if the request is awaiting a decision.
   */
  public function isPending(): bool {
    return $this === self::Pending;
  }

  /**
   * Returns all statuses as a key => label map for select elements.
   *
   * @return array<string, string>
   */
  public static function options(): array {
    $options = [];
    foreach (self::cases() as $case) {
      $options[$case->value] = $case->label();
    }
    return $options;
  }

}
