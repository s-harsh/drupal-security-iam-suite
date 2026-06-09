<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Value;

/**
 * Immutable value object representing the outcome of the flood guard pipeline.
 *
 * The 'reason' field carries one of: 'ip', 'user', 'reputation', 'allowlist', 'passed'.
 */
final readonly class FloodDecision {

  public function __construct(
    public readonly bool $allowed,
    public readonly string $reason,
    public readonly string $identifier,
    public readonly int $retryAfter = 0,
  ) {}

  /**
   * Creates an "allowed" decision (request passed all checks).
   */
  public static function pass(string $identifier = ''): self {
    return new self(
      allowed: true,
      reason: 'passed',
      identifier: $identifier,
    );
  }

  /**
   * Creates an "allowed" decision because the IP is allowlisted.
   */
  public static function allowlisted(string $identifier): self {
    return new self(
      allowed: true,
      reason: 'allowlist',
      identifier: $identifier,
    );
  }

  /**
   * Creates a "blocked" decision with the triggering reason and retry window.
   */
  public static function block(string $reason, string $identifier, int $retryAfter = 0): self {
    return new self(
      allowed: false,
      reason: $reason,
      identifier: $identifier,
      retryAfter: $retryAfter,
    );
  }

}
