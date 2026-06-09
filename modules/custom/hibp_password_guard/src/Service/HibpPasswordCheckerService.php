<?php

declare(strict_types=1);

namespace Drupal\hibp_password_guard\Service;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\hibp_password_guard\Value\HibpCheckResult;
use Psr\Log\LoggerInterface;

/**
 * Orchestrates the full HIBP password check pipeline.
 *
 * Responsibilities:
 *   - Compute the SHA-1 hash of the candidate password.
 *   - Split the hash into a 5-character prefix and 35-character suffix.
 *   - Check the cache for a previously stored range response.
 *   - On cache miss, call HibpApiClient::fetchRange() to retrieve the range.
 *   - Parse the SUFFIX:COUNT response lines (CRLF-delimited).
 *   - Perform a case-insensitive suffix match.
 *   - Apply fail-open or fail-closed degradation on API failure.
 *   - Return a typed HibpCheckResult value object.
 *
 * Security note: the plaintext password is hashed immediately on entry and
 * never stored, logged, or passed downstream. Only the 5-character prefix
 * is transmitted over the network via HibpApiClient.
 */
final class HibpPasswordCheckerService {

  /**
   * The config object name.
   */
  private const CONFIG_NAME = 'hibp_password_guard.settings';

  /**
   * Cache key prefix for stored HIBP range responses.
   */
  private const CACHE_KEY_PREFIX = 'hibp_range:';

  /**
   * Constructs an HibpPasswordCheckerService.
   *
   * @param \Drupal\hibp_password_guard\Service\HibpApiClient $apiClient
   *   The HIBP API client.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache
   *   The dedicated HIBP cache bin.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The module logger channel.
   */
  public function __construct(
    private readonly HibpApiClient $apiClient,
    private readonly CacheBackendInterface $cache,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Checks whether a plaintext password appears in the HIBP breach database.
   *
   * @param string $password
   *   The candidate plaintext password. Used only to compute the SHA-1 hash;
   *   it is not stored, logged, or passed to any external service.
   * @param bool $bypassCache
   *   When TRUE, skips the cache read and forces a fresh API call. The
   *   result is still written to the cache on success. Used by Drush.
   *
   * @return \Drupal\hibp_password_guard\Value\HibpCheckResult
   *   The result object indicating pwned status, breach count, or API error.
   */
  public function check(string $password, bool $bypassCache = false): HibpCheckResult {
    $config = $this->configFactory->get(self::CONFIG_NAME);

    // If the module is globally disabled, always pass without any HTTP call.
    if (!(bool) $config->get('enabled')) {
      return new HibpCheckResult(isPwned: false, breachCount: 0);
    }

    // Compute SHA-1 hash entirely in-process; the plaintext is released to GC.
    $hash = strtoupper(hash('sha1', $password));
    $prefix = substr($hash, 0, 5);
    $suffix = substr($hash, 5);

    // Attempt to read the range body from cache unless bypassing.
    $rangeBody = null;
    if (!$bypassCache) {
      $cacheItem = $this->cache->get(self::CACHE_KEY_PREFIX . $prefix);
      if ($cacheItem !== FALSE) {
        $rangeBody = (string) $cacheItem->data;
        $this->logger->debug('HIBP cache hit for range request.');
      }
    }

    // On cache miss (or bypass), call the API.
    if ($rangeBody === null) {
      $response = $this->apiClient->fetchRange($prefix);

      if (!$response->success) {
        $failMode = (string) $config->get('fail_mode');
        $this->logger->notice(
          'HIBP API unavailable during password check. Fail mode: @mode. Error: @error',
          ['@mode' => $failMode, '@error' => $response->errorMessage],
        );

        if ($failMode === 'fail_closed') {
          return new HibpCheckResult(
            isPwned: true,
            breachCount: 0,
            apiError: true,
            errorType: $response->errorMessage,
          );
        }

        // fail_open: return clean pass on API error.
        return new HibpCheckResult(
          isPwned: false,
          breachCount: 0,
          apiError: true,
          errorType: $response->errorMessage,
        );
      }

      $rangeBody = $response->body;

      // Write the successful response to cache.
      $cacheTtl = (int) $config->get('cache_ttl');
      if ($cacheTtl > 0) {
        $this->cache->set(
          self::CACHE_KEY_PREFIX . $prefix,
          $rangeBody,
          time() + $cacheTtl,
        );
      }
    }

    // Parse the SUFFIX:COUNT lines and check for a match.
    return $this->parseRangeBody($rangeBody, $suffix);
  }

  /**
   * Parses the HIBP range response body and checks for the given suffix.
   *
   * @param string $body
   *   The CRLF-delimited SUFFIX:COUNT response body from the HIBP API.
   * @param string $suffix
   *   The 35-character uppercase hex suffix to search for.
   *
   * @return \Drupal\hibp_password_guard\Value\HibpCheckResult
   *   The check result.
   */
  private function parseRangeBody(string $body, string $suffix): HibpCheckResult {
    $lines = explode("\r\n", trim($body));

    foreach ($lines as $line) {
      $line = trim($line);
      if ($line === '') {
        continue;
      }

      $parts = explode(':', $line, 2);
      if (count($parts) !== 2) {
        continue;
      }

      [$responseSuffix, $countString] = $parts;
      $count = (int) $countString;

      // Discard padding entries (count == 0).
      if ($count === 0) {
        continue;
      }

      if (strcasecmp(trim($responseSuffix), $suffix) === 0) {
        return new HibpCheckResult(isPwned: true, breachCount: $count);
      }
    }

    return new HibpCheckResult(isPwned: false, breachCount: 0);
  }

}
