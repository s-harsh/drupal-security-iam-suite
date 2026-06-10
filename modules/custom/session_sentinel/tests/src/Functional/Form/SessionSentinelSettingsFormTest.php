<?php

declare(strict_types=1);

namespace Drupal\Tests\session_sentinel\Functional\Form;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the Session Sentinel settings form.
 *
 * Verifies that the form renders, saves values correctly, and validates
 * invalid input server-side.
 *
 * @group session_sentinel
 */
final class SessionSentinelSettingsFormTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['session_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Admin user with administer session sentinel permission.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $adminUser;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->adminUser = $this->drupalCreateUser(['administer session sentinel']);
    $this->drupalLogin($this->adminUser);
  }

  /**
   * Tests that the settings form is accessible to admins.
   */
  public function testSettingsFormIsAccessible(): void {
    $this->drupalGet('/admin/config/security/session-sentinel');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('Session Sentinel Settings');
  }

  /**
   * Tests that the settings form is not accessible to anonymous users.
   */
  public function testSettingsFormRequiresAuthentication(): void {
    $this->drupalLogout();
    $this->drupalGet('/admin/config/security/session-sentinel');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that valid settings are saved correctly.
   */
  public function testValidSettingsAreSaved(): void {
    $this->drupalGet('/admin/config/security/session-sentinel');
    $this->assertSession()->statusCodeEquals(200);

    $this->submitForm([
      'idle_timeout'             => 2400,
      'warning_lead_time'        => 120,
      'max_concurrent_sessions'  => 5,
      'exempt_admins_from_limit' => 1,
      'enable_device_binding'    => 1,
      'kill_on_device_change'    => 0,
      'prune_age'                => 86400,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');

    $config = $this->config('session_sentinel.settings');
    $this->assertSame(2400, $config->get('idle_timeout'));
    $this->assertSame(120, $config->get('warning_lead_time'));
    $this->assertSame(5, $config->get('max_concurrent_sessions'));
    $this->assertTrue($config->get('exempt_admins_from_limit'));
    $this->assertTrue($config->get('enable_device_binding'));
    $this->assertFalse($config->get('kill_on_device_change'));
    $this->assertSame(86400, $config->get('prune_age'));
  }

  /**
   * Tests that warning_lead_time >= idle_timeout triggers a validation error.
   */
  public function testWarningLeadTimeCannotExceedIdleTimeout(): void {
    $this->drupalGet('/admin/config/security/session-sentinel');

    $this->submitForm([
      'idle_timeout'      => 600,
      'warning_lead_time' => 600,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Warning lead time must be less than the idle timeout');
  }

  /**
   * Tests that a negative idle_timeout is rejected.
   */
  public function testNegativeIdleTimeoutIsRejected(): void {
    $this->drupalGet('/admin/config/security/session-sentinel');

    $this->submitForm([
      'idle_timeout' => -1,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Idle timeout cannot be negative');
  }

  /**
   * Tests that a prune_age below 3600 is rejected.
   */
  public function testPruneAgeBelowMinimumIsRejected(): void {
    $this->drupalGet('/admin/config/security/session-sentinel');

    $this->submitForm([
      'idle_timeout' => 1800,
      'warning_lead_time' => 300,
      'prune_age' => 1800,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Prune age must be at least 3600 seconds');
  }

  /**
   * Tests setting idle_timeout to 0 disables idle timeout.
   */
  public function testIdleTimeoutZeroDisablesTimeout(): void {
    $this->drupalGet('/admin/config/security/session-sentinel');

    $this->submitForm([
      'idle_timeout'      => 0,
      'warning_lead_time' => 300,
      'max_concurrent_sessions' => 3,
      'prune_age' => 604800,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $config = $this->config('session_sentinel.settings');
    $this->assertSame(0, $config->get('idle_timeout'));
  }

  /**
   * Tests setting max_concurrent_sessions to 0 allows unlimited sessions.
   */
  public function testMaxConcurrentSessionsZeroAllowsUnlimited(): void {
    $this->drupalGet('/admin/config/security/session-sentinel');

    $this->submitForm([
      'idle_timeout'            => 1800,
      'warning_lead_time'       => 300,
      'max_concurrent_sessions' => 0,
      'prune_age'               => 604800,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $config = $this->config('session_sentinel.settings');
    $this->assertSame(0, $config->get('max_concurrent_sessions'));
  }

}
