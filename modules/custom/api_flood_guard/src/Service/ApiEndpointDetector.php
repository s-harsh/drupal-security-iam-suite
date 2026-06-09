<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Detects API endpoint requests and extracts credential identifiers.
 *
 * Encapsulates path matching logic (prefix vs. exact), HTML form detection,
 * and username/client_id extraction from Authorization headers and request
 * bodies. Extracted identifiers are SHA-256-hashed before being returned.
 */
final class ApiEndpointDetector {

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * Returns TRUE if the request targets a configured protected API path.
   *
   * Checks the request path against the protected_paths configuration,
   * applying either prefix or exact matching per entry.
   */
  public function isProtectedPath(Request $request): bool {
    $path = $request->getPathInfo();
    $config = $this->configFactory->get('api_flood_guard.settings');
    $protectedPaths = $config->get('protected_paths') ?? [];

    foreach ($protectedPaths as $entry) {
      $entryPath = $entry['path'] ?? '';
      $matchType = $entry['match'] ?? 'exact';

      if ($entryPath === '') {
        continue;
      }

      if ($matchType === 'prefix' && str_starts_with($path, $entryPath)) {
        return TRUE;
      }

      if ($matchType === 'exact' && $path === $entryPath) {
        return TRUE;
      }
    }

    return FALSE;
  }

  /**
   * Returns TRUE if this is an HTML form submission that core should handle.
   *
   * Specifically, a POST to /user/login with Content-Type
   * application/x-www-form-urlencoded and without ?_format=json is a standard
   * Drupal form submission and should not be intercepted by API Flood Guard.
   */
  public function isHtmlFormSubmission(Request $request): bool {
    $path = $request->getPathInfo();
    $contentType = $request->headers->get('Content-Type', '');
    $format = $request->query->get('_format', '');

    // Only apply to /user/login path.
    if ($path !== '/user/login') {
      return FALSE;
    }

    // If the format is JSON, it's an API request.
    if ($format === 'json') {
      return FALSE;
    }

    // If Content-Type contains application/json, it's an API request.
    if (str_contains($contentType, 'application/json')) {
      return FALSE;
    }

    // If it's a form-urlencoded submission, it's an HTML form.
    if (str_contains($contentType, 'application/x-www-form-urlencoded')) {
      return TRUE;
    }

    // GET requests to /user/login are the login form page load — skip.
    if ($request->isMethod('GET')) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * Extracts and hashes the username or client identifier from the request.
   *
   * Checks (in order):
   *   1. Authorization: Basic header — base64-decoded username portion.
   *   2. JSON request body — 'username' field (REST login) or 'client_id' (OAuth).
   *   3. Form-encoded body — 'username' or 'client_id' fields.
   *
   * The raw identifier is normalized (trim + strtolower) then hashed with
   * SHA-256 before being returned, to avoid storing raw usernames anywhere.
   *
   * @return string
   *   SHA-256 hash of the normalized identifier, or empty string if none found.
   */
  public function extractUsernameIdentifier(Request $request): string {
    $raw = $this->extractRawIdentifier($request);

    if ($raw === '') {
      return '';
    }

    $normalized = strtolower(trim($raw));

    return hash('sha256', $normalized);
  }

  /**
   * Extracts the raw identifier without hashing (for internal use only).
   */
  private function extractRawIdentifier(Request $request): string {
    // 1. Check Authorization: Basic header.
    $authHeader = $request->headers->get('Authorization', '');
    if (str_starts_with($authHeader, 'Basic ')) {
      $encoded = substr($authHeader, 6);
      $decoded = base64_decode($encoded, TRUE);

      if ($decoded !== FALSE && str_contains($decoded, ':')) {
        // Split on first colon only; username may not contain colons but password might.
        $colonPos = strpos($decoded, ':');
        $username = substr($decoded, 0, $colonPos);

        if ($username !== '') {
          return $username;
        }
      }
      // Malformed Authorization header — return empty (no flood tracking).
      return '';
    }

    // 2. Try JSON body.
    $contentType = $request->headers->get('Content-Type', '');
    if (str_contains($contentType, 'application/json')) {
      $body = $request->getContent();
      if ($body !== '') {
        $decoded = json_decode($body, TRUE);
        if (is_array($decoded)) {
          // REST user login uses 'name'.
          if (isset($decoded['name']) && is_string($decoded['name']) && $decoded['name'] !== '') {
            return $decoded['name'];
          }
          // Also check 'username'.
          if (isset($decoded['username']) && is_string($decoded['username']) && $decoded['username'] !== '') {
            return $decoded['username'];
          }
          // OAuth2 token endpoint uses 'client_id'.
          if (isset($decoded['client_id']) && is_string($decoded['client_id']) && $decoded['client_id'] !== '') {
            return $decoded['client_id'];
          }
        }
      }
      return '';
    }

    // 3. Try form-encoded body (OAuth token endpoint with grant_type=password/client_credentials).
    if (str_contains($contentType, 'application/x-www-form-urlencoded') || $request->request->count() > 0) {
      $clientId = $request->request->get('client_id', '');
      if (is_string($clientId) && $clientId !== '') {
        return $clientId;
      }
      $username = $request->request->get('username', '');
      if (is_string($username) && $username !== '') {
        return $username;
      }
    }

    return '';
  }

}
