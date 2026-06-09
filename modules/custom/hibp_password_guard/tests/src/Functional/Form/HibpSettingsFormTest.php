<?php

declare(strict_types=1);

namespace Drupal\Tests\hibp_password_guard\Functional\Form;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the HIBP Password Guard admin settings form.
 *
 * Exercises the full HTTP request cycle: page load, form rendering, validation,
 * save, and config readback. Tests run against a real Drupal installation with
 * the module enabled.
 *
 * @group hibp_password_guard
 */
final class HibpSettingsFormTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['hibp_password_guard', 'password_policy'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * The admin settings page path.
   */
  private const SETTINGS_PATH = '/admin/config/security/hibp-password-guard';

  // -------------------------------------------------------------------------
  // Access control
  // -------------------------------------------------------------------------

  /**
   * Tests that anonymous users are redirected away from the settings form.
   */
  public function testAnonymousUserCannotAccessSettingsForm(): void {
    $this->drupalGet(self::SETTINGS_PATH);
    // Anonymous users are redirected to the login page (302/200 after redirect).
    $this->assertSession()->addressNotEquals(self::SETTINGS_PATH);
  }

  /**
   * Tests that a user without the specific permission receives HTTP 403.
   */
  public function testUserWithoutPermissionReceives403(): void {
    $user = $this->drupalCreateUser(['access administration pages']);
    $this->drupalLogin($user);

    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that a user with 'administer hibp password guard' can access the form.
   */
  public function testUserWithPermissionCanAccessSettingsForm(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);

    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that a site administrator (all permissions) can access the form.
   */
  public function testAdministratorCanAccessSettingsForm(): void {
    $admin = $this->drupalCreateUser([], null, true);
    $this->drupalLogin($admin);

    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->statusCodeEquals(200);
  }

  // -------------------------------------------------------------------------
  // Form rendering
  // -------------------------------------------------------------------------

  /**
   * Tests that the page title is correct.
   */
  public function testSettingsFormHasCorrectPageTitle(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);

    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->titleContains('HIBP Password Guard');
  }

  /**
   * Tests that all five expected form fields are present.
   */
  public function testSettingsFormRendersAllFiveFields(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->assertSession()->fieldExists('enabled');
    $this->assertSession()->fieldExists('cache_ttl');
    $this->assertSession()->fieldExists('http_timeout');
    $this->assertSession()->fieldExists('api_base_url');
    $this->assertSession()->fieldExists('fail_mode');
  }

  /**
   * Tests that the form has a save button.
   */
  public function testSettingsFormHasSaveButton(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->assertSession()->buttonExists('Save configuration');
  }

  /**
   * Tests that default values from config/install are pre-populated.
   */
  public function testSettingsFormShowsInstalledDefaults(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    // Default values from config/install/hibp_password_guard.settings.yml.
    $this->assertSession()->fieldValueEquals('api_base_url', 'https://api.pwnedpasswords.com');
    $this->assertSession()->fieldValueEquals('cache_ttl', '86400');
    $this->assertSession()->fieldValueEquals('http_timeout', '5');
  }

  /**
   * Tests that the fail_mode radios show both options.
   */
  public function testSettingsFormShowsBothFailModeOptions(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->assertSession()->pageTextContains('Fail open');
    $this->assertSession()->pageTextContains('Fail closed');
  }

  // -------------------------------------------------------------------------
  // Successful save
  // -------------------------------------------------------------------------

  /**
   * Tests that submitting valid data produces a status message.
   */
  public function testSubmittingValidDataShowsConfirmationMessage(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '3600',
      'http_timeout' => '10',
      'api_base_url' => 'https://api.pwnedpasswords.com',
      'fail_mode'    => 'fail_closed',
    ], 'Save configuration');

    $this->assertSession()->statusMessageContains('The configuration options have been saved.');
  }

  /**
   * Tests that all five configuration values are persisted correctly.
   */
  public function testSavePersistsAllFiveConfigValues(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '7200',
      'http_timeout' => '15',
      'api_base_url' => 'https://api.pwnedpasswords.com',
      'fail_mode'    => 'fail_closed',
    ], 'Save configuration');

    $config = $this->config('hibp_password_guard.settings');
    $this->assertTrue((bool) $config->get('enabled'));
    $this->assertSame(7200, (int) $config->get('cache_ttl'));
    $this->assertSame(15, (int) $config->get('http_timeout'));
    $this->assertSame('https://api.pwnedpasswords.com', $config->get('api_base_url'));
    $this->assertSame('fail_closed', $config->get('fail_mode'));
  }

  /**
   * Tests that disabling the module (enabled=false) is saved correctly.
   */
  public function testSavingEnabledFalsePersists(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => FALSE,
      'cache_ttl'    => '86400',
      'http_timeout' => '5',
      'api_base_url' => 'https://api.pwnedpasswords.com',
      'fail_mode'    => 'fail_open',
    ], 'Save configuration');

    $config = $this->config('hibp_password_guard.settings');
    $this->assertFalse((bool) $config->get('enabled'));
  }

  /**
   * Tests that cache_ttl=0 (caching disabled) is a valid value and saves correctly.
   */
  public function testCacheTtlOfZeroIsValidAndSaves(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '0',
      'http_timeout' => '5',
      'api_base_url' => 'https://api.pwnedpasswords.com',
      'fail_mode'    => 'fail_open',
    ], 'Save configuration');

    $this->assertSession()->statusMessageContains('The configuration options have been saved.');
    $this->assertSame(0, (int) $this->config('hibp_password_guard.settings')->get('cache_ttl'));
  }

  /**
   * Tests saving with the minimum allowed timeout (1 second).
   */
  public function testMinimumHttpTimeoutOfOneSaves(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '86400',
      'http_timeout' => '1',
      'api_base_url' => 'https://api.pwnedpasswords.com',
      'fail_mode'    => 'fail_open',
    ], 'Save configuration');

    $this->assertSession()->statusMessageContains('The configuration options have been saved.');
  }

  /**
   * Tests saving with the maximum allowed timeout (30 seconds).
   */
  public function testMaximumHttpTimeoutOf30Saves(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '86400',
      'http_timeout' => '30',
      'api_base_url' => 'https://api.pwnedpasswords.com',
      'fail_mode'    => 'fail_open',
    ], 'Save configuration');

    $this->assertSession()->statusMessageContains('The configuration options have been saved.');
  }

  // -------------------------------------------------------------------------
  // Validation failures
  // -------------------------------------------------------------------------

  /**
   * Tests that a negative cache_ttl value fails validation.
   */
  public function testNegativeCacheTtlFailsValidation(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '-1',
      'http_timeout' => '5',
      'api_base_url' => 'https://api.pwnedpasswords.com',
      'fail_mode'    => 'fail_open',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Cache TTL must be a non-negative integer');
  }

  /**
   * Tests that http_timeout below minimum (0) fails validation.
   */
  public function testHttpTimeoutBelowMinimumFailsValidation(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '86400',
      'http_timeout' => '0',
      'api_base_url' => 'https://api.pwnedpasswords.com',
      'fail_mode'    => 'fail_open',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('HTTP timeout must be an integer between 1 and 30');
  }

  /**
   * Tests that http_timeout above maximum (31) fails validation.
   */
  public function testHttpTimeoutAboveMaximumFailsValidation(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '86400',
      'http_timeout' => '31',
      'api_base_url' => 'https://api.pwnedpasswords.com',
      'fail_mode'    => 'fail_open',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('HTTP timeout must be an integer between 1 and 30');
  }

  /**
   * Tests that a non-absolute URL fails api_base_url validation.
   */
  public function testRelativeApiBaseUrlFailsValidation(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '86400',
      'http_timeout' => '5',
      'api_base_url' => '/relative/path',
      'fail_mode'    => 'fail_open',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('HIBP API base URL must be a valid absolute URL');
  }

  /**
   * Tests that a completely invalid string fails api_base_url validation.
   */
  public function testInvalidApiBaseUrlFailsValidation(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '86400',
      'http_timeout' => '5',
      'api_base_url' => 'not-a-url',
      'fail_mode'    => 'fail_open',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('HIBP API base URL must be a valid absolute URL');
  }

  /**
   * Tests that a validation error does NOT save any config changes.
   */
  public function testValidationFailureDoesNotPersistChanges(): void {
    $user = $this->drupalCreateUser(['administer hibp password guard']);
    $this->drupalLogin($user);

    // Read the current api_base_url to verify it is unchanged after failure.
    $originalUrl = (string) $this->config('hibp_password_guard.settings')->get('api_base_url');

    $this->drupalGet(self::SETTINGS_PATH);
    $this->submitForm([
      'enabled'      => TRUE,
      'cache_ttl'    => '-999',          // Invalid: will fail validation.
      'http_timeout' => '5',
      'api_base_url' => 'https://api.pwnedpasswords.com',
      'fail_mode'    => 'fail_open',
    ], 'Save configuration');

    // Config must remain unchanged.
    $config = $this->config('hibp_password_guard.settings');
    $this->assertSame($originalUrl, $config->get('api_base_url'));
  }

  // -------------------------------------------------------------------------
  // Menu and navigation
  // -------------------------------------------------------------------------

  /**
   * Tests that the settings page is linked from the Security admin menu section.
   */
  public function testSettingsPageIsReachableFromAdminMenu(): void {
    $user = $this->drupalCreateUser([
      'administer hibp password guard',
      'access administration pages',
    ]);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/config/security');
    $this->assertSession()->statusCodeEquals(200);

    // The settings link should appear somewhere in the Security section.
    $this->assertSession()->linkByHrefExists(self::SETTINGS_PATH);
  }

}
