<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Functional\Plugin\IpReputation;

use Drupal\Tests\BrowserTestBase;

/**
 * Integration/functional tests for the AbuseIPDB plugin wiring.
 *
 * These tests verify the configuration pathway and the fail-open behavior
 * accessible through the full Drupal kernel without live API calls.
 *
 * @group api_flood_guard
 */
class AbuseIpDbIntegrationTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'api_flood_guard',
    'rest',
    'serialization',
    'basic_auth',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    // Use a very high flood threshold so IP/user flood never triggers;
    // we test reputation configuration here.
    $this->config('api_flood_guard.settings')
      ->set('protected_paths', [
        ['path' => '/user/login', 'match' => 'exact'],
      ])
      ->set('ip_threshold', 500)
      ->set('ip_window', 3600)
      ->set('user_threshold', 500)
      ->set('user_window', 900)
      ->set('response_code', 429)
      ->set('block_message', 'Too many authentication requests. Please wait before trying again.')
      ->save();
  }

  // -------------------------------------------------------------------------
  // Configuration — stored correctly
  // -------------------------------------------------------------------------

  /**
   * Tests that the abuseipdb provider can be configured via the settings form.
   */
  public function testAbuseIpDbProviderConfigIsStoredCorrectly(): void {
    $this->config('api_flood_guard.settings')
      ->set('reputation_providers.enabled_provider', 'abuseipdb')
      ->set('reputation_providers.abuseipdb.api_key', 'test-key-12345')
      ->set('reputation_providers.abuseipdb.threshold', 85)
      ->set('reputation_providers.abuseipdb.max_age_days', 30)
      ->set('reputation_providers.abuseipdb.cache_ttl', 3600)
      ->save();

    $config = $this->config('api_flood_guard.settings');
    $this->assertSame('abuseipdb', $config->get('reputation_providers.enabled_provider'));
    $this->assertSame('test-key-12345', $config->get('reputation_providers.abuseipdb.api_key'));
    $this->assertSame(85, $config->get('reputation_providers.abuseipdb.threshold'));
    $this->assertSame(30, $config->get('reputation_providers.abuseipdb.max_age_days'));
    $this->assertSame(3600, $config->get('reputation_providers.abuseipdb.cache_ttl'));
  }

  // -------------------------------------------------------------------------
  // Fail-open — no API key configured
  // -------------------------------------------------------------------------

  /**
   * Tests fail-open: when api_key is empty, reputation check is skipped.
   *
   * The plugin returns IpReputationResult::allowed() when not configured,
   * and the FloodManager proceeds to flood checks normally.
   */
  public function testFailOpenWhenProviderApiKeyIsEmpty(): void {
    $this->config('api_flood_guard.settings')
      ->set('reputation_providers.enabled_provider', 'abuseipdb')
      ->set('reputation_providers.abuseipdb.api_key', '')
      ->save();

    // Requests should NOT be blocked by reputation (no key = no check).
    $this->drupalGet('/user/login', ['query' => ['_format' => 'json']]);
    $this->assertSession()->statusCodeNotEquals(429);
  }

  /**
   * Tests that disabling the reputation provider (empty enabled_provider) skips the check.
   */
  public function testDisabledProviderSkipsReputationCheck(): void {
    $this->config('api_flood_guard.settings')
      ->set('reputation_providers.enabled_provider', '')
      ->save();

    $this->drupalGet('/user/login', ['query' => ['_format' => 'json']]);
    $this->assertSession()->statusCodeNotEquals(429);
  }

  /**
   * Tests that null_provider string is treated as disabled.
   */
  public function testNullProviderStringIsDisabled(): void {
    $this->config('api_flood_guard.settings')
      ->set('reputation_providers.enabled_provider', 'null_provider')
      ->save();

    $this->drupalGet('/user/login', ['query' => ['_format' => 'json']]);
    $this->assertSession()->statusCodeNotEquals(429);
  }

  // -------------------------------------------------------------------------
  // Plugin manager — abuseipdb plugin is discoverable
  // -------------------------------------------------------------------------

  /**
   * Tests that the IpReputationManager can instantiate the abuseipdb plugin.
   */
  public function testAbuseIpDbPluginIsDiscoverableByManager(): void {
    /** @var \Drupal\api_flood_guard\Plugin\Manager\IpReputationManager $manager */
    $manager = \Drupal::service('plugin.manager.ip_reputation');

    $definitions = $manager->getDefinitions();
    $this->assertArrayHasKey('abuseipdb', $definitions);
    $this->assertArrayHasKey('null_provider', $definitions);
  }

  /**
   * Tests that the NullProvider plugin can be instantiated via the manager.
   */
  public function testNullProviderCanBeInstantiatedViaManager(): void {
    /** @var \Drupal\api_flood_guard\Plugin\Manager\IpReputationManager $manager */
    $manager = \Drupal::service('plugin.manager.ip_reputation');
    $plugin = $manager->createInstance('null_provider');

    $this->assertFalse($plugin->isConfigured());

    $result = $plugin->checkIp('1.2.3.4');
    $this->assertFalse($result->isBlocked);
    $this->assertFalse($result->providerError);
  }

  /**
   * Tests that the AbuseIPDB plugin can be instantiated via the manager.
   */
  public function testAbuseIpDbPluginCanBeInstantiatedViaManager(): void {
    /** @var \Drupal\api_flood_guard\Plugin\Manager\IpReputationManager $manager */
    $manager = \Drupal::service('plugin.manager.ip_reputation');
    $plugin = $manager->createInstance('abuseipdb');

    // Without an API key configured, isConfigured() should return FALSE.
    $this->assertFalse($plugin->isConfigured());
  }

  // -------------------------------------------------------------------------
  // Cache bin is available
  // -------------------------------------------------------------------------

  /**
   * Tests that the api_flood_guard cache bin is available and usable.
   */
  public function testApiFloodGuardCacheBinIsAvailable(): void {
    /** @var \Drupal\Core\Cache\CacheBackendInterface $cache */
    $cache = \Drupal::cache('api_flood_guard');

    $cache->set('test_key', ['value' => 'test_data'], time() + 60);
    $cached = $cache->get('test_key');

    $this->assertNotFalse($cached);
    $this->assertSame(['value' => 'test_data'], $cached->data);

    $cache->delete('test_key');
  }

  // -------------------------------------------------------------------------
  // Settings form wires to provider config
  // -------------------------------------------------------------------------

  /**
   * Tests that saving the settings form with abuseipdb threshold persists the value.
   */
  public function testSettingsFormSavesAbuseIpDbThreshold(): void {
    $adminUser = $this->drupalCreateUser(['administer api flood guard']);
    $this->drupalLogin($adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'    => 100,
      'ip_window'       => 3600,
      'user_threshold'  => 20,
      'user_window'     => 900,
      'response_code'   => 429,
      'block_message'   => 'Too many requests.',
      'allowlist'       => '',
      'protected_paths' => 'exact:/user/login',
      'threshold'       => 75,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $this->assertSame(75, $this->config('api_flood_guard.settings')->get('reputation_providers.abuseipdb.threshold'));
  }

}
