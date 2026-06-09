<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Contract;

use Drupal\api_flood_guard\Value\IpReputationResult;

/**
 * Plugin contract for IP reputation provider plugins.
 *
 * Implementations must be fail-open: on any provider error (network failure,
 * invalid API key, rate limit exceeded), return an IpReputationResult with
 * isBlocked = false and providerError = true rather than throwing exceptions.
 */
interface IpReputationProviderInterface {

  /**
   * Checks the given IP address against the reputation provider.
   *
   * @param string $ip
   *   The client IP address (IPv4 or IPv6).
   *
   * @return \Drupal\api_flood_guard\Value\IpReputationResult
   *   The reputation check result. Must never throw; fail-open on error.
   */
  public function checkIp(string $ip): IpReputationResult;

  /**
   * Returns TRUE if the plugin has sufficient configuration to perform checks.
   *
   * For example, returns FALSE when the API key is empty. When FALSE, the
   * ApiFloodManager will skip the reputation check entirely.
   *
   * @return bool
   *   Whether the provider is ready to perform IP reputation checks.
   */
  public function isConfigured(): bool;

  /**
   * Returns the plugin's ID as declared in its annotation.
   *
   * @return string
   *   The plugin ID.
   */
  public function getPluginId(): string;

  /**
   * Returns the full plugin definition.
   *
   * @return mixed
   *   The plugin definition.
   */
  public function getPluginDefinition(): mixed;

}
