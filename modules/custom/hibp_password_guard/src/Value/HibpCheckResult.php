<?php

declare(strict_types=1);

namespace Drupal\hibp_password_guard\Value;

/**
 * Immutable value object representing the outcome of an HIBP password check.
 *
 * Returned by HibpPasswordCheckerService::check() to convey whether the
 * password was found in a breach, how many times it appeared, and whether
 * an API error occurred (as opposed to a clean not-found result).
 */
final readonly class HibpCheckResult {

  /**
   * Constructs an HibpCheckResult.
   *
   * @param bool $isPwned
   *   TRUE if the password hash was found in the HIBP breach database.
   * @param int $breachCount
   *   The number of times the password appeared in breach records. 0 if not
   *   pwned or if the API was unavailable.
   * @param bool $apiError
   *   TRUE if the HIBP API could not be reached or returned a non-200 response.
   * @param string $errorType
   *   A short description of the error type (e.g. exception class name or HTTP
   *   status code string). Never contains password or hash data.
   */
  public function __construct(
    public readonly bool $isPwned,
    public readonly int $breachCount,
    public readonly bool $apiError = false,
    public readonly string $errorType = '',
  ) {}

}
