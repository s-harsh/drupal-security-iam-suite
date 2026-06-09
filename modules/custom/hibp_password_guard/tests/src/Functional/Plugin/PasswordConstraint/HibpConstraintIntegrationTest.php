<?php

declare(strict_types=1);

namespace Drupal\Tests\hibp_password_guard\Functional\Plugin\PasswordConstraint;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional integration tests for the HibpCompromised password constraint plugin.
 *
 * These tests exercise the full Drupal service container including the real
 * HibpPasswordCheckerService. Tests that require an outbound API call are
 * grouped as 'requires_network' so they can be skipped in offline CI.
 * Tests that do NOT require network access are in the base 'hibp_password_guard'
 * group and use an unreachable or disabled API.
 *
 * @group hibp_password_guard
 */
final class HibpConstraintIntegrationTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['hibp_password_guard', 'password_policy'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  // -------------------------------------------------------------------------
  // Plugin discovery
  // -------------------------------------------------------------------------

  /**
   * Tests that the hibp_compromised plugin is registered in the plugin manager.
   */
  public function testHibpCompromisedPluginIsDiscoverable(): void {
    /** @var \Drupal\password_policy\PasswordConstraintManager $manager */
    $manager = $this->container->get('plugin.manager.password_constraint');
    $definitions = $manager->getDefinitions();

    $this->assertArrayHasKey('hibp_compromised', $definitions,
      'The hibp_compromised plugin must be registered with the password constraint manager.');
  }

  /**
   * Tests that the plugin label is non-empty.
   */
  public function testHibpCompromisedPluginHasNonEmptyLabel(): void {
    /** @var \Drupal\password_policy\PasswordConstraintManager $manager */
    $manager = $this->container->get('plugin.manager.password_constraint');
    $definitions = $manager->getDefinitions();

    $this->assertArrayHasKey('hibp_compromised', $definitions);
    $label = (string) ($definitions['hibp_compromised']['label'] ?? '');
    $this->assertNotEmpty($label, 'The plugin label must not be empty.');
  }

  /**
   * Tests that the plugin description references the HIBP breach database.
   */
  public function testHibpCompromisedPluginHasDescription(): void {
    /** @var \Drupal\password_policy\PasswordConstraintManager $manager */
    $manager = $this->container->get('plugin.manager.password_constraint');
    $definitions = $manager->getDefinitions();

    $this->assertArrayHasKey('hibp_compromised', $definitions);
    $description = (string) ($definitions['hibp_compromised']['description'] ?? '');
    $this->assertNotEmpty($description);
    $this->assertStringContainsStringIgnoringCase('Have I Been Pwned', $description);
  }

  // -------------------------------------------------------------------------
  // Module enabled/disabled config
  // -------------------------------------------------------------------------

  /**
   * Tests that disabling the module via config causes check() to always pass.
   */
  public function testCheckAlwaysPassesWhenModuleIsDisabled(): void {
    $this->config('hibp_password_guard.settings')
      ->set('enabled', false)
      ->save();

    /** @var \Drupal\hibp_password_guard\Service\HibpPasswordCheckerService $checker */
    $checker = $this->container->get('hibp_password_guard.checker');

    // "password" is in HIBP with millions of occurrences, but the module is
    // disabled so it must always return not-pwned with no API call.
    $result = $checker->check('password');

    $this->assertFalse($result->isPwned);
    $this->assertFalse($result->apiError);
    $this->assertSame(0, $result->breachCount);
  }

  /**
   * Tests that enabling the module via config allows checks to proceed.
   */
  public function testCheckProceedsWhenModuleIsEnabled(): void {
    $this->config('hibp_password_guard.settings')
      ->set('enabled', true)
      ->set('api_base_url', 'https://127.0.0.1:1') // Unreachable — forces API error.
      ->set('http_timeout', 1)
      ->set('fail_mode', 'fail_open')
      ->save();

    /** @var \Drupal\hibp_password_guard\Service\HibpPasswordCheckerService $checker */
    $checker = $this->container->get('hibp_password_guard.checker');
    $result = $checker->check('password');

    // Module is enabled so a check was attempted; the API error flag should be set.
    $this->assertTrue($result->apiError,
      'When enabled, check() must attempt an API call and set apiError on failure.');
  }

  // -------------------------------------------------------------------------
  // Fail-mode integration
  // -------------------------------------------------------------------------

  /**
   * Tests that fail_open mode returns isPwned=false on API connectivity error.
   */
  public function testFailOpenReturnsFalseOnApiError(): void {
    $this->config('hibp_password_guard.settings')
      ->set('enabled', true)
      ->set('fail_mode', 'fail_open')
      ->set('api_base_url', 'https://127.0.0.1:1')
      ->set('http_timeout', 1)
      ->set('cache_ttl', 0)
      ->save();

    /** @var \Drupal\hibp_password_guard\Service\HibpPasswordCheckerService $checker */
    $checker = $this->container->get('hibp_password_guard.checker');
    $result = $checker->check('password');

    $this->assertFalse($result->isPwned,
      'fail_open must return isPwned=false when API is unreachable.');
    $this->assertTrue($result->apiError,
      'fail_open must set apiError=true when API is unreachable.');
  }

  /**
   * Tests that fail_closed mode returns isPwned=true on API connectivity error.
   */
  public function testFailClosedReturnsTrueOnApiError(): void {
    $this->config('hibp_password_guard.settings')
      ->set('enabled', true)
      ->set('fail_mode', 'fail_closed')
      ->set('api_base_url', 'https://127.0.0.1:1')
      ->set('http_timeout', 1)
      ->set('cache_ttl', 0)
      ->save();

    /** @var \Drupal\hibp_password_guard\Service\HibpPasswordCheckerService $checker */
    $checker = $this->container->get('hibp_password_guard.checker');
    $result = $checker->check('password');

    $this->assertTrue($result->isPwned,
      'fail_closed must return isPwned=true when API is unreachable.');
    $this->assertTrue($result->apiError);
    $this->assertSame(0, $result->breachCount,
      'fail_closed API error must have breachCount=0.');
  }

  // -------------------------------------------------------------------------
  // Cache TTL config
  // -------------------------------------------------------------------------

  /**
   * Tests that cache_ttl=0 disables caching (checker service does not crash).
   */
  public function testCacheTtlZeroDoesNotCrash(): void {
    $this->config('hibp_password_guard.settings')
      ->set('enabled', true)
      ->set('cache_ttl', 0)
      ->set('api_base_url', 'https://127.0.0.1:1')
      ->set('http_timeout', 1)
      ->set('fail_mode', 'fail_open')
      ->save();

    /** @var \Drupal\hibp_password_guard\Service\HibpPasswordCheckerService $checker */
    $checker = $this->container->get('hibp_password_guard.checker');

    // Should not throw — fail_open with unreachable API returns cleanly.
    $result = $checker->check('anypassword');
    $this->assertFalse($result->isPwned);
  }

  // -------------------------------------------------------------------------
  // Service container wiring
  // -------------------------------------------------------------------------

  /**
   * Tests that the checker service is registered in the container.
   */
  public function testCheckerServiceIsRegisteredInContainer(): void {
    $checker = $this->container->get('hibp_password_guard.checker');

    $this->assertInstanceOf(
      \Drupal\hibp_password_guard\Service\HibpPasswordCheckerService::class,
      $checker,
    );
  }

  /**
   * Tests that the api_client service is registered in the container.
   */
  public function testApiClientServiceIsRegisteredInContainer(): void {
    $client = $this->container->get('hibp_password_guard.api_client');

    $this->assertInstanceOf(
      \Drupal\hibp_password_guard\Service\HibpApiClient::class,
      $client,
    );
  }

}
