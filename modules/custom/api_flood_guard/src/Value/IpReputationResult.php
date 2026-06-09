<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Value;

/**
 * Immutable value object returned by IP reputation provider plugins.
 */
final readonly class IpReputationResult {

  public function __construct(
    public readonly bool $isBlocked,
    public readonly int $confidenceScore,
    public readonly array $abuseCategories = [],
    public readonly string $providerName = '',
    public readonly bool $fromCache = false,
    public readonly bool $providerError = false,
  ) {}

  /**
   * Creates a fail-open result indicating a provider error occurred.
   */
  public static function failOpen(string $providerName = ''): self {
    return new self(
      isBlocked: false,
      confidenceScore: 0,
      abuseCategories: [],
      providerName: $providerName,
      fromCache: false,
      providerError: true,
    );
  }

  /**
   * Creates an allowed (not blocked) result with no error.
   */
  public static function allowed(int $score = 0, string $providerName = '', bool $fromCache = false): self {
    return new self(
      isBlocked: false,
      confidenceScore: $score,
      providerName: $providerName,
      fromCache: $fromCache,
    );
  }

  /**
   * Creates a blocked result.
   */
  public static function blocked(int $score, string $providerName = '', array $categories = [], bool $fromCache = false): self {
    return new self(
      isBlocked: true,
      confidenceScore: $score,
      abuseCategories: $categories,
      providerName: $providerName,
      fromCache: $fromCache,
    );
  }

}
