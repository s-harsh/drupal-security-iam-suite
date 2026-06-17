<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Authenticates SCIM API requests using configurable Bearer tokens.
 *
 * Each IdP is assigned a unique Bearer token, stored as a SHA-256 hash in
 * configuration. Incoming requests are accepted when the hashed value of the
 * presented token matches any active entry in the idp_tokens list.
 *
 * Token comparison is performed using hash_equals() to prevent timing-based
 * side-channel attacks.
 */
final class ScimAuthenticator {

  /**
   * Config object name for SCIM Bridge settings.
   */
  private const CONFIG_NAME = 'scim_bridge.settings';

  /**
   * Constructs a ScimAuthenticator.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The SCIM Bridge logger channel.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Returns the IdP label if the request carries a valid Bearer token.
   *
   * Extracts the Authorization header, strips the "Bearer " prefix, hashes
   * the raw token with SHA-256, and compares it to each active entry.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming HTTP request.
   *
   * @return string|null
   *   The matching IdP label string, or NULL when authentication fails.
   */
  public function authenticate(Request $request): ?string {
    $config = $this->configFactory->get(self::CONFIG_NAME);

    if (!(bool) $config->get('enabled')) {
      $this->logger->notice('SCIM Bridge is disabled; rejecting request.');
      return null;
    }

    $authHeader = $request->headers->get('Authorization', '');
    if (!str_starts_with((string) $authHeader, 'Bearer ')) {
      return null;
    }

    $rawToken  = substr((string) $authHeader, 7);
    $hashedToken = hash('sha256', $rawToken);

    $tokens = (array) ($config->get('idp_tokens') ?? []);
    foreach ($tokens as $entry) {
      if (!is_array($entry)) {
        continue;
      }
      if (empty($entry['enabled'])) {
        continue;
      }
      $storedHash = (string) ($entry['token'] ?? '');
      if ($storedHash === '') {
        continue;
      }
      if (hash_equals($storedHash, $hashedToken)) {
        return (string) ($entry['label'] ?? 'unknown');
      }
    }

    $this->logger->notice('SCIM request rejected: no matching active token. Remote IP: @ip', [
      '@ip' => $request->getClientIp(),
    ]);
    return null;
  }

  /**
   * Hashes a raw Bearer token for storage in configuration.
   *
   * @param string $rawToken
   *   The plain-text token as issued to the IdP.
   *
   * @return string
   *   SHA-256 hex digest of the token.
   */
  public static function hashToken(string $rawToken): string {
    return hash('sha256', $rawToken);
  }

}
