<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Service;

use Drupal\api_flood_guard\Plugin\Manager\IpReputationManager;
use Drupal\api_flood_guard\Value\FloodDecision;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Flood\FloodInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Orchestrates the full multi-stage flood guard decision pipeline.
 *
 * Pipeline stages (in order):
 *   1. CIDR allowlist check — allowlisted IPs bypass everything.
 *   2. IP reputation check — blocked IPs are rejected immediately.
 *   3. Per-IP flood check — IPs exceeding the threshold are blocked.
 *   4. Per-username flood check — identifiers exceeding threshold are blocked.
 *   5. Flood counter registration — both counters are incremented for passing requests.
 *
 * Returns a FloodDecision value object; never throws.
 */
final class ApiFloodManager {

  public function __construct(
    private readonly FloodInterface $flood,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
    private readonly IpReputationManager $reputationManager,
  ) {}

  /**
   * Evaluates a request through the full flood guard pipeline.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming request.
   * @param string $clientIp
   *   The client IP address extracted from the request.
   * @param string $usernameHash
   *   SHA-256 hash of the normalized username or client_id, or empty string
   *   if no identifier was found in the request.
   *
   * @return \Drupal\api_flood_guard\Value\FloodDecision
   *   The pipeline decision.
   */
  public function evaluate(Request $request, string $clientIp, string $usernameHash): FloodDecision {
    $config = $this->configFactory->get('api_flood_guard.settings');

    // Stage 1: CIDR allowlist check.
    $allowlist = $config->get('allowlist') ?? [];
    if ($this->isAllowlisted($clientIp, $allowlist)) {
      $debugLogging = (bool) ($config->get('debug_logging') ?? FALSE);
      if ($debugLogging) {
        $this->logger->debug(
          'API Flood Guard: allowlisted IP @ip passed path @path.',
          ['@ip' => $clientIp, '@path' => $request->getPathInfo()]
        );
      }
      return FloodDecision::allowlisted($clientIp);
    }

    // Stage 2: IP reputation check.
    $enabledProvider = (string) ($config->get('reputation_providers.enabled_provider') ?? '');
    if ($enabledProvider !== '' && $enabledProvider !== 'null_provider') {
      try {
        $plugin = $this->reputationManager->createInstance($enabledProvider);
        if ($plugin->isConfigured()) {
          $result = $plugin->checkIp($clientIp);
          if (!$result->providerError && $result->isBlocked) {
            $this->logger->warning(
              'API Flood Guard: blocked IP @ip by reputation provider @provider (score: @score) on path @path.',
              [
                '@ip'       => $clientIp,
                '@provider' => $result->providerName,
                '@score'    => $result->confidenceScore,
                '@path'     => $request->getPathInfo(),
              ]
            );
            return FloodDecision::block(
              reason: 'reputation',
              identifier: $clientIp,
              retryAfter: (int) ($config->get('ip_window') ?? 3600),
            );
          }
        }
      }
      catch (\Exception $e) {
        $this->logger->warning(
          'API Flood Guard: reputation provider @provider threw an exception for IP @ip: @message (fail-open).',
          [
            '@provider' => $enabledProvider,
            '@ip'       => $clientIp,
            '@message'  => $e->getMessage(),
          ]
        );
        // Fail-open: proceed to flood checks.
      }
    }

    // Stage 3: Per-IP flood check.
    $ipThreshold = (int) ($config->get('ip_threshold') ?? 100);
    $ipWindow = (int) ($config->get('ip_window') ?? 3600);

    if (!$this->flood->isAllowed('api_flood_guard.ip', $ipThreshold, $ipWindow, $clientIp)) {
      $this->logger->warning(
        'API Flood Guard: blocked IP @ip (exceeded @threshold requests in @window seconds) on path @path.',
        [
          '@ip'        => $clientIp,
          '@threshold' => $ipThreshold,
          '@window'    => $ipWindow,
          '@path'      => $request->getPathInfo(),
        ]
      );
      return FloodDecision::block(
        reason: 'ip',
        identifier: $clientIp,
        retryAfter: $ipWindow,
      );
    }

    // Stage 4: Per-username flood check.
    $userThreshold = (int) ($config->get('user_threshold') ?? 20);
    $userWindow = (int) ($config->get('user_window') ?? 900);

    if ($usernameHash !== '' && !$this->flood->isAllowed('api_flood_guard.user', $userThreshold, $userWindow, $usernameHash)) {
      $this->logger->warning(
        'API Flood Guard: blocked username identifier @id (exceeded @threshold requests in @window seconds) on path @path.',
        [
          '@id'        => substr($usernameHash, 0, 8),
          '@threshold' => $userThreshold,
          '@window'    => $userWindow,
          '@path'      => $request->getPathInfo(),
        ]
      );
      return FloodDecision::block(
        reason: 'user',
        identifier: $usernameHash,
        retryAfter: $userWindow,
      );
    }

    // Stage 5: Register flood counters.
    $this->flood->register('api_flood_guard.ip', $ipWindow, $clientIp);
    if ($usernameHash !== '') {
      $this->flood->register('api_flood_guard.user', $userWindow, $usernameHash);
    }

    $debugLogging = (bool) ($config->get('debug_logging') ?? FALSE);
    if ($debugLogging) {
      $this->logger->debug(
        'API Flood Guard: allowed request from IP @ip on path @path.',
        ['@ip' => $clientIp, '@path' => $request->getPathInfo()]
      );
    }

    return FloodDecision::pass($clientIp);
  }

  /**
   * Clears the per-username flood counter on successful authentication.
   *
   * Called by the RESPONSE subscriber when a protected path returns HTTP 200.
   */
  public function clearUserFlood(string $usernameHash): void {
    if ($usernameHash !== '') {
      $this->flood->clear('api_flood_guard.user', $usernameHash);
    }
  }

  /**
   * Clears all flood entries for a specific IP address.
   */
  public function clearIpFlood(string $ip): void {
    $this->flood->clear('api_flood_guard.ip', $ip);
  }

  /**
   * Checks whether a given IP address is covered by any allowlist CIDR entry.
   *
   * Supports IPv4 and IPv6 addresses and CIDR ranges. Uses native PHP
   * inet_pton() and bitwise operations — no third-party library required.
   *
   * @param string $ip
   *   The client IP address to check.
   * @param array $allowlist
   *   Array of CIDR strings (e.g. '10.0.0.0/8', '::1').
   *
   * @return bool
   *   TRUE if the IP falls within any configured allowlist entry.
   */
  private function isAllowlisted(string $ip, array $allowlist): bool {
    if (empty($allowlist)) {
      return FALSE;
    }

    $ipBinary = @inet_pton($ip);
    if ($ipBinary === FALSE) {
      // Malformed IP — fail-open (do not allowlist).
      return FALSE;
    }

    foreach ($allowlist as $cidr) {
      $cidr = trim((string) $cidr);
      if ($cidr === '') {
        continue;
      }

      if ($this->ipMatchesCidr($ipBinary, $cidr)) {
        return TRUE;
      }
    }

    return FALSE;
  }

  /**
   * Tests whether a pre-parsed IP binary matches a CIDR entry.
   */
  private function ipMatchesCidr(string $ipBinary, string $cidr): bool {
    if (str_contains($cidr, '/')) {
      [$cidrIp, $prefixLen] = explode('/', $cidr, 2);
      $prefixLen = (int) $prefixLen;
    }
    else {
      $cidrIp = $cidr;
      $prefixLen = -1; // Exact match.
    }

    $cidrBinary = @inet_pton($cidrIp);
    if ($cidrBinary === FALSE) {
      return FALSE;
    }

    // IP and CIDR must be the same address family.
    if (strlen($ipBinary) !== strlen($cidrBinary)) {
      return FALSE;
    }

    $byteLen = strlen($ipBinary);

    if ($prefixLen === -1) {
      // Exact match.
      return $ipBinary === $cidrBinary;
    }

    $maxPrefix = $byteLen * 8;
    if ($prefixLen < 0 || $prefixLen > $maxPrefix) {
      return FALSE;
    }

    // Compare the first $prefixLen bits.
    $fullBytes = (int) ($prefixLen / 8);
    $remainingBits = $prefixLen % 8;

    // Check full bytes.
    if ($fullBytes > 0 && substr($ipBinary, 0, $fullBytes) !== substr($cidrBinary, 0, $fullBytes)) {
      return FALSE;
    }

    // Check partial byte if needed.
    if ($remainingBits > 0 && $fullBytes < $byteLen) {
      $mask = 0xFF & (0xFF << (8 - $remainingBits));
      $ipByte = ord($ipBinary[$fullBytes]);
      $cidrByte = ord($cidrBinary[$fullBytes]);
      if (($ipByte & $mask) !== ($cidrByte & $mask)) {
        return FALSE;
      }
    }

    return TRUE;
  }

}
