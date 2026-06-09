<?php

declare(strict_types=1);

namespace Drupal\hibp_password_guard\Value;

/**
 * Immutable value object representing the raw HTTP response from the HIBP API.
 *
 * Returned by HibpApiClient::fetchRange() to decouple the HTTP transport
 * layer from the parsing and business logic in HibpPasswordCheckerService.
 */
final readonly class HibpRangeResponse {

  /**
   * Constructs an HibpRangeResponse.
   *
   * @param bool $success
   *   TRUE if the API returned HTTP 200 with a parseable body.
   * @param string $body
   *   The raw CRLF-delimited SUFFIX:COUNT response body. Empty on failure.
   * @param int $statusCode
   *   The HTTP status code returned by the API. 0 if a connection-level
   *   exception occurred before a response was received.
   * @param string $errorMessage
   *   A sanitised error description containing only the exception class name
   *   or HTTP status code. Never contains password or hash data.
   */
  public function __construct(
    public readonly bool $success,
    public readonly string $body = '',
    public readonly int $statusCode = 0,
    public readonly string $errorMessage = '',
  ) {}

}
