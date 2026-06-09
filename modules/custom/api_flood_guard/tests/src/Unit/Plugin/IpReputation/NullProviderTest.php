<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Unit\Plugin\IpReputation;

use Drupal\api_flood_guard\Plugin\IpReputation\NullProvider;
use Drupal\Tests\UnitTestCase;

/**
 * Unit tests for the NullProvider IP reputation plugin.
 *
 * @group api_flood_guard
 * @coversDefaultClass \Drupal\api_flood_guard\Plugin\IpReputation\NullProvider
 */
final class NullProviderTest extends UnitTestCase {

  /**
   * Plugin definition for use in tests.
   */
  private array $pluginDefinition = [
    'id'           => 'null_provider',
    'label'        => 'None (disabled)',
    'description'  => 'Disables IP reputation checking.',
    'api_endpoint' => '',
  ];

  /**
   * Returns an instantiated NullProvider plugin.
   */
  private function buildPlugin(): NullProvider {
    return new NullProvider([], 'null_provider', $this->pluginDefinition);
  }

  /**
   * Tests that isConfigured() always returns FALSE.
   *
   * @covers ::isConfigured
   */
  public function testIsConfiguredAlwaysReturnsFalse(): void {
    $plugin = $this->buildPlugin();
    $this->assertFalse($plugin->isConfigured());
  }

  /**
   * Tests that checkIp() returns an allowed result for any IP.
   *
   * @covers ::checkIp
   */
  public function testCheckIpAlwaysReturnsAllowed(): void {
    $plugin = $this->buildPlugin();
    $result = $plugin->checkIp('1.2.3.4');

    $this->assertFalse($result->isBlocked);
    $this->assertSame('null_provider', $result->providerName);
    $this->assertFalse($result->providerError);
    $this->assertSame(0, $result->confidenceScore);
  }

  /**
   * Tests that checkIp() returns allowed for an IPv6 address.
   *
   * @covers ::checkIp
   */
  public function testCheckIpReturnsAllowedForIpv6(): void {
    $plugin = $this->buildPlugin();
    $result = $plugin->checkIp('::1');

    $this->assertFalse($result->isBlocked);
    $this->assertSame('null_provider', $result->providerName);
  }

  /**
   * Tests that checkIp() does not set fromCache for null provider results.
   *
   * @covers ::checkIp
   */
  public function testCheckIpDoesNotSetFromCache(): void {
    $plugin = $this->buildPlugin();
    $result = $plugin->checkIp('10.0.0.1');

    $this->assertFalse($result->fromCache);
  }

  /**
   * Tests that checkIp() returns same shape for any arbitrary IP string.
   *
   * @covers ::checkIp
   */
  public function testCheckIpAlwaysAllowsArbitraryInput(): void {
    $plugin = $this->buildPlugin();

    foreach (['0.0.0.0', '255.255.255.255', '192.168.1.1', '2001:db8::1'] as $ip) {
      $result = $plugin->checkIp($ip);
      $this->assertFalse($result->isBlocked, "Expected NullProvider to allow IP: $ip");
    }
  }

}
