<?php

declare(strict_types=1);

namespace Drupal\session_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Generates and compares device fingerprints for session binding.
 *
 * The fingerprint is a SHA-256 digest of:
 *   - The User-Agent string (or empty string if absent).
 *   - The /24 (IPv4) or /48 (IPv6) subnet derived from the client IP.
 *
 * Using the subnet rather than the exact IP allows the fingerprint to survive
 * DHCP reassignments within the same network while still detecting users
 * moving between radically different networks.
 */
final class DeviceFingerprintService {

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Generates a device fingerprint for the given request.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request Incoming HTTP request.
   *
   * @return string 64-character hexadecimal SHA-256 fingerprint.
   */
  public function generate(Request $request): string {
    $userAgent = (string) ($request->headers->get('User-Agent') ?? '');
    $clientIp = (string) ($request->getClientIp() ?? '');
    $subnet = $this->extractSubnet($clientIp);

    return hash('sha256', $userAgent . '|' . $subnet);
  }

  /**
   * Generates a fingerprint from raw User-Agent and IP strings.
   *
   * This variant is useful in contexts where you have already extracted the
   * values and do not have a Request object available (e.g. Drush commands).
   *
   * @param string $userAgent User-Agent string.
   * @param string $ipAddress Client IP address.
   *
   * @return string 64-character hexadecimal SHA-256 fingerprint.
   */
  public function generateFromStrings(string $userAgent, string $ipAddress): string {
    $subnet = $this->extractSubnet($ipAddress);
    return hash('sha256', $userAgent . '|' . $subnet);
  }

  /**
   * Compares two fingerprints in constant time to prevent timing attacks.
   *
   * @param string $a First fingerprint.
   * @param string $b Second fingerprint.
   *
   * @return bool TRUE if the fingerprints match.
   */
  public function matches(string $a, string $b): bool {
    return hash_equals($a, $b);
  }

  /**
   * Determines whether device binding is enabled in configuration.
   *
   * @return bool
   */
  public function isEnabled(): bool {
    return (bool) $this->configFactory
      ->get('session_sentinel.settings')
      ->get('enable_device_binding');
  }

  /**
   * Determines whether sessions should be killed on fingerprint mismatch.
   *
   * When this returns FALSE, mismatches are flagged and logged but the session
   * is not terminated.
   *
   * @return bool
   */
  public function killOnChange(): bool {
    return (bool) $this->configFactory
      ->get('session_sentinel.settings')
      ->get('kill_on_device_change');
  }

  /**
   * Extracts the network subnet from a client IP address.
   *
   * For IPv4 addresses, returns the /24 (first three octets, e.g. "10.0.1").
   * For IPv6 addresses, returns the /48 (first three groups, e.g. "2001:db8:1").
   * Returns an empty string for invalid or unresolvable addresses.
   *
   * @param string $ip Raw IP address string.
   *
   * @return string Subnet string used in fingerprint derivation.
   */
  public function extractSubnet(string $ip): string {
    if ($ip === '') {
      return '';
    }

    // Attempt to resolve "::ffff:x.x.x.x" IPv4-mapped IPv6 to pure IPv4.
    if (str_starts_with($ip, '::ffff:') || str_starts_with($ip, '::FFFF:')) {
      $ip = substr($ip, 7);
    }

    // IPv4: return the /24 subnet (first three octets).
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE) {
      $parts = explode('.', $ip, 4);
      return $parts[0] . '.' . $parts[1] . '.' . $parts[2];
    }

    // IPv6: return the /48 subnet (first three groups).
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE) {
      // Expand the compressed IPv6 address for reliable splitting.
      $expanded = $this->expandIPv6($ip);
      if ($expanded !== '') {
        $groups = explode(':', $expanded, 9);
        return $groups[0] . ':' . $groups[1] . ':' . $groups[2];
      }
    }

    // Unrecognised format — log once and return empty.
    $this->logger->debug(
      'Session Sentinel: unable to extract subnet from IP address "@ip". Fingerprint will use empty subnet.',
      ['@ip' => $ip]
    );

    return '';
  }

  /**
   * Expands a compressed IPv6 address to its full 8-group notation.
   *
   * Uses inet_pton() + inet_ntop() to round-trip through the binary
   * representation, which always yields the full uncompressed form on PHP.
   *
   * @param string $ip Compressed or full IPv6 address.
   *
   * @return string Full IPv6 address string, or empty string on failure.
   */
  private function expandIPv6(string $ip): string {
    $binary = @inet_pton($ip);
    if ($binary === FALSE) {
      return '';
    }
    // inet_ntop() on 16-byte binary always returns the compressed canonical
    // form. We need the padded full form for reliable 3-group extraction.
    $hex = bin2hex($binary);
    // Split into 8 groups of 4 hex chars.
    $groups = str_split($hex, 4);
    return implode(':', $groups);
  }

}
