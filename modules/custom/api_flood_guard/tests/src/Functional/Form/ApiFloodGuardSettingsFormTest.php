<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Functional\Form;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the API Flood Guard settings form.
 *
 * @group api_flood_guard
 */
class ApiFloodGuardSettingsFormTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['api_flood_guard', 'dblog'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Admin user with full administer permission.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $adminUser;

  /**
   * User with no special permissions.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $unprivilegedUser;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->adminUser = $this->drupalCreateUser(['administer api flood guard']);
    $this->unprivilegedUser = $this->drupalCreateUser(['access content']);
  }

  // -------------------------------------------------------------------------
  // Access control
  // -------------------------------------------------------------------------

  /**
   * Tests that an admin user can access the settings page (HTTP 200).
   */
  public function testAdminCanAccessSettingsPage(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that the settings page title is present.
   */
  public function testSettingsPageTitle(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');
    $this->assertSession()->pageTextContains('API Flood Guard Settings');
  }

  /**
   * Tests that an anonymous user is denied access (HTTP 403).
   */
  public function testAnonymousUserIsDeniedAccess(): void {
    $this->drupalGet('/admin/config/security/api-flood-guard');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that a logged-in unprivileged user is denied access (HTTP 403).
   */
  public function testUnprivilegedUserIsDeniedAccess(): void {
    $this->drupalLogin($this->unprivilegedUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');
    $this->assertSession()->statusCodeEquals(403);
  }

  // -------------------------------------------------------------------------
  // Form fields present
  // -------------------------------------------------------------------------

  /**
   * Tests that the protected paths textarea is present.
   */
  public function testProtectedPathsFieldIsPresent(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');
    $this->assertSession()->fieldExists('protected_paths');
  }

  /**
   * Tests that the ip_threshold number field is present.
   */
  public function testIpThresholdFieldIsPresent(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');
    $this->assertSession()->fieldExists('ip_threshold');
  }

  /**
   * Tests that the user_threshold number field is present.
   */
  public function testUserThresholdFieldIsPresent(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');
    $this->assertSession()->fieldExists('user_threshold');
  }

  /**
   * Tests that the allowlist textarea is present.
   */
  public function testAllowlistFieldIsPresent(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');
    $this->assertSession()->fieldExists('allowlist');
  }

  /**
   * Tests that the response_code select field is present.
   */
  public function testResponseCodeSelectIsPresent(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');
    $this->assertSession()->fieldExists('response_code');
  }

  // -------------------------------------------------------------------------
  // Form save — happy path
  // -------------------------------------------------------------------------

  /**
   * Tests that valid threshold values are saved correctly.
   */
  public function testFormSavesThresholds(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'    => 50,
      'ip_window'       => 1800,
      'user_threshold'  => 10,
      'user_window'     => 600,
      'response_code'   => 429,
      'block_message'   => 'Rate limit exceeded.',
      'allowlist'       => '',
      'protected_paths' => "prefix:/jsonapi\nexact:/user/login",
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');

    $config = $this->config('api_flood_guard.settings');
    $this->assertSame(50, $config->get('ip_threshold'));
    $this->assertSame(1800, $config->get('ip_window'));
    $this->assertSame(10, $config->get('user_threshold'));
    $this->assertSame(600, $config->get('user_window'));
  }

  /**
   * Tests that the block_message is saved correctly.
   */
  public function testFormSavesBlockMessage(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 429,
      'block_message'  => 'Custom block message for testing.',
      'allowlist'      => '',
      'protected_paths'=> 'exact:/user/login',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $this->assertSame(
      'Custom block message for testing.',
      $this->config('api_flood_guard.settings')->get('block_message'),
    );
  }

  /**
   * Tests that a valid IPv4 allowlist entry is saved.
   */
  public function testFormSavesValidIpv4AllowlistEntry(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 429,
      'block_message'  => 'Too many requests.',
      'allowlist'      => "127.0.0.1\n10.0.0.0/8",
      'protected_paths'=> 'exact:/user/login',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $allowlist = $this->config('api_flood_guard.settings')->get('allowlist');
    $this->assertContains('127.0.0.1', $allowlist);
    $this->assertContains('10.0.0.0/8', $allowlist);
  }

  /**
   * Tests that response_code = 503 is saved correctly.
   */
  public function testFormSaves503ResponseCode(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 503,
      'block_message'  => 'Service unavailable.',
      'allowlist'      => '',
      'protected_paths'=> 'exact:/user/login',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $this->assertSame(503, $this->config('api_flood_guard.settings')->get('response_code'));
  }

  /**
   * Tests that protected_paths are saved as structured entries.
   */
  public function testProtectedPathsSavedAsStructuredData(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 429,
      'block_message'  => 'Too many requests.',
      'allowlist'      => '',
      'protected_paths'=> "prefix:/jsonapi\nexact:/oauth/token",
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $paths = $this->config('api_flood_guard.settings')->get('protected_paths');
    $this->assertIsArray($paths);
    $this->assertCount(2, $paths);

    // Verify first entry.
    $this->assertSame('prefix', $paths[0]['match']);
    $this->assertSame('/jsonapi', $paths[0]['path']);
    // Verify second entry.
    $this->assertSame('exact', $paths[1]['match']);
    $this->assertSame('/oauth/token', $paths[1]['path']);
  }

  // -------------------------------------------------------------------------
  // Validation — error cases
  // -------------------------------------------------------------------------

  /**
   * Tests that an invalid CIDR range produces a form validation error.
   */
  public function testInvalidCidrInAllowlistProducesValidationError(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 429,
      'block_message'  => 'Too many requests.',
      'allowlist'      => '999.999.0.0/8',
      'protected_paths'=> 'exact:/user/login',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Invalid IP address or CIDR range');
    // Config should NOT be saved on validation failure.
    $this->assertNotEquals('999.999.0.0/8', implode('', $this->config('api_flood_guard.settings')->get('allowlist') ?? []));
  }

  /**
   * Tests that an invalid protected path format produces a validation error.
   */
  public function testInvalidProtectedPathFormatProducesValidationError(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 429,
      'block_message'  => 'Too many requests.',
      'allowlist'      => '',
      'protected_paths'=> 'invalid-format-without-colon',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Invalid path entry');
  }

  /**
   * Tests that a protected path without leading slash produces a validation error.
   */
  public function testProtectedPathWithoutLeadingSlashProducesError(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 429,
      'block_message'  => 'Too many requests.',
      'allowlist'      => '',
      'protected_paths'=> 'exact:noleadingslash',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('must begin with a forward slash');
  }

  /**
   * Tests that ip_threshold below 1 produces a validation error.
   */
  public function testIpThresholdBelowOneProducesError(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 0,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 429,
      'block_message'  => 'Too many requests.',
      'allowlist'      => '',
      'protected_paths'=> 'exact:/user/login',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Per-IP threshold must be a positive integer');
  }

  /**
   * Tests that ip_window below 60 produces a validation error.
   */
  public function testIpWindowBelowMinimumProducesError(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 30,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 429,
      'block_message'  => 'Too many requests.',
      'allowlist'      => '',
      'protected_paths'=> 'exact:/user/login',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Per-IP window must be between 60 and 86400 seconds');
  }

  /**
   * Tests that user_window above 86400 produces a validation error.
   */
  public function testUserWindowAboveMaximumProducesError(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 99999,
      'response_code'  => 429,
      'block_message'  => 'Too many requests.',
      'allowlist'      => '',
      'protected_paths'=> 'exact:/user/login',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Per-username window must be between 60 and 86400 seconds');
  }

  /**
   * Tests that a valid IPv6 allowlist entry is accepted.
   */
  public function testValidIpv6AllowlistEntryIsAccepted(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 429,
      'block_message'  => 'Too many requests.',
      'allowlist'      => '::1',
      'protected_paths'=> 'exact:/user/login',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $this->assertContains('::1', $this->config('api_flood_guard.settings')->get('allowlist'));
  }

  /**
   * Tests that the debug_logging checkbox can be saved as true.
   */
  public function testDebugLoggingCheckboxCanBeSavedAsTrue(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard');

    $this->submitForm([
      'ip_threshold'   => 100,
      'ip_window'      => 3600,
      'user_threshold' => 20,
      'user_window'    => 900,
      'response_code'  => 429,
      'block_message'  => 'Too many requests.',
      'allowlist'      => '',
      'protected_paths'=> 'exact:/user/login',
      'debug_logging'  => TRUE,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $this->assertTrue((bool) $this->config('api_flood_guard.settings')->get('debug_logging'));
  }

}
