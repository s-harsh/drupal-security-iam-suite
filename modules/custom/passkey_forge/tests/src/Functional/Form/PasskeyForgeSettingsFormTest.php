<?php

declare(strict_types=1);

namespace Drupal\Tests\passkey_forge\Functional\Form;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the Passkey Forge admin settings form.
 *
 * Exercises the full HTTP request cycle: page access control, form rendering,
 * input validation, config persistence, and navigation. Tests run against a
 * real Drupal installation with the module enabled.
 *
 * @group passkey_forge
 */
final class PasskeyForgeSettingsFormTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['passkey_forge'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Path to the settings form.
   */
  private const SETTINGS_PATH = '/admin/config/security/passkey-forge';

  // -------------------------------------------------------------------------
  // Access control
  // -------------------------------------------------------------------------

  /**
   * Tests that anonymous users are redirected away from the settings form.
   */
  public function testAnonymousUserCannotAccessSettingsForm(): void {
    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->addressNotEquals(self::SETTINGS_PATH);
  }

  /**
   * Tests that a user without the permission receives HTTP 403.
   */
  public function testUserWithoutPermissionReceives403(): void {
    $user = $this->drupalCreateUser(['access administration pages']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that a user with 'administer passkey forge' can access the form.
   */
  public function testUserWithPermissionCanAccessSettingsForm(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that a site administrator can access the form.
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
   * Tests that the page title contains 'Passkey Forge'.
   */
  public function testSettingsFormHasCorrectTitle(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->titleContains('Passkey Forge');
  }

  /**
   * Tests that all expected form fields are present.
   */
  public function testSettingsFormRendersAllFields(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->assertSession()->fieldExists('enabled');
    $this->assertSession()->fieldExists('rp_id');
    $this->assertSession()->fieldExists('rp_name');
    $this->assertSession()->fieldExists('allowed_origins');
    $this->assertSession()->fieldExists('attestation_policy');
    $this->assertSession()->fieldExists('timeout');
    $this->assertSession()->fieldExists('user_verification');
    $this->assertSession()->fieldExists('require_resident_key');
    $this->assertSession()->fieldExists('allow_password_fallback');
    $this->assertSession()->fieldExists('challenge_ttl');
  }

  /**
   * Tests that the form has a save button.
   */
  public function testSettingsFormHasSaveButton(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->buttonExists('Save configuration');
  }

  /**
   * Tests that the attestation policy radios show all three options.
   */
  public function testSettingsFormShowsAllAttestationPolicies(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->assertSession()->pageTextContains('None');
    $this->assertSession()->pageTextContains('Indirect');
    $this->assertSession()->pageTextContains('Direct');
  }

  /**
   * Tests that user_verification radios show all three options.
   */
  public function testSettingsFormShowsAllUserVerificationOptions(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->assertSession()->pageTextContains('Required');
    $this->assertSession()->pageTextContains('Preferred');
    $this->assertSession()->pageTextContains('Discouraged');
  }

  // -------------------------------------------------------------------------
  // Successful save
  // -------------------------------------------------------------------------

  /**
   * Tests that submitting valid data shows the confirmation message.
   */
  public function testSubmittingValidDataShowsConfirmationMessage(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled' => TRUE,
      'rp_id' => 'testsite.example.com',
      'rp_name' => 'Test Site',
      'allowed_origins' => 'https://testsite.example.com',
      'attestation_policy' => 'none',
      'timeout' => '60000',
      'user_verification' => 'preferred',
      'require_resident_key' => FALSE,
      'allow_password_fallback' => TRUE,
      'challenge_ttl' => '300',
    ], 'Save configuration');

    $this->assertSession()->statusMessageContains('The configuration options have been saved.');
  }

  /**
   * Tests that all config values are persisted after a valid save.
   */
  public function testSavePersistsAllConfigValues(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled' => TRUE,
      'rp_id' => 'rp.example.org',
      'rp_name' => 'RP Name',
      'allowed_origins' => "https://rp.example.org\nhttps://alt.example.org",
      'attestation_policy' => 'indirect',
      'timeout' => '90000',
      'user_verification' => 'required',
      'require_resident_key' => TRUE,
      'allow_password_fallback' => FALSE,
      'challenge_ttl' => '120',
    ], 'Save configuration');

    $config = $this->config('passkey_forge.settings');
    $this->assertTrue((bool) $config->get('enabled'));
    $this->assertSame('rp.example.org', $config->get('rp_id'));
    $this->assertSame('RP Name', $config->get('rp_name'));
    $this->assertContains('https://rp.example.org', (array) $config->get('allowed_origins'));
    $this->assertContains('https://alt.example.org', (array) $config->get('allowed_origins'));
    $this->assertSame('indirect', $config->get('attestation_policy'));
    $this->assertSame(90000, (int) $config->get('timeout'));
    $this->assertSame('required', $config->get('user_verification'));
    $this->assertTrue((bool) $config->get('require_resident_key'));
    $this->assertFalse((bool) $config->get('allow_password_fallback'));
    $this->assertSame(120, (int) $config->get('challenge_ttl'));
  }

  // -------------------------------------------------------------------------
  // Validation failures
  // -------------------------------------------------------------------------

  /**
   * Tests that an empty RP ID fails validation.
   */
  public function testEmptyRpIdFailsValidation(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled' => TRUE,
      'rp_id' => '',
      'rp_name' => 'Test',
      'allowed_origins' => 'https://example.com',
      'attestation_policy' => 'none',
      'timeout' => '60000',
      'user_verification' => 'preferred',
      'require_resident_key' => FALSE,
      'allow_password_fallback' => TRUE,
      'challenge_ttl' => '300',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Relying Party ID is required');
  }

  /**
   * Tests that an invalid domain RP ID fails validation.
   */
  public function testInvalidRpIdDomainFailsValidation(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled' => TRUE,
      'rp_id' => 'not a domain!!',
      'rp_name' => 'Test',
      'allowed_origins' => 'https://example.com',
      'attestation_policy' => 'none',
      'timeout' => '60000',
      'user_verification' => 'preferred',
      'require_resident_key' => FALSE,
      'allow_password_fallback' => TRUE,
      'challenge_ttl' => '300',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('valid domain name');
  }

  /**
   * Tests that a relative URL in allowed_origins fails validation.
   */
  public function testRelativeOriginFailsValidation(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled' => TRUE,
      'rp_id' => 'example.com',
      'rp_name' => 'Test',
      'allowed_origins' => '/relative/path',
      'attestation_policy' => 'none',
      'timeout' => '60000',
      'user_verification' => 'preferred',
      'require_resident_key' => FALSE,
      'allow_password_fallback' => TRUE,
      'challenge_ttl' => '300',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('valid absolute URL');
  }

  /**
   * Tests that a timeout below minimum fails validation.
   */
  public function testTimeoutBelowMinimumFailsValidation(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled' => TRUE,
      'rp_id' => 'example.com',
      'rp_name' => 'Test',
      'allowed_origins' => 'https://example.com',
      'attestation_policy' => 'none',
      'timeout' => '999',
      'user_verification' => 'preferred',
      'require_resident_key' => FALSE,
      'allow_password_fallback' => TRUE,
      'challenge_ttl' => '300',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('10000');
  }

  /**
   * Tests that a challenge TTL above maximum fails validation.
   */
  public function testChallengeTtlAboveMaximumFailsValidation(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled' => TRUE,
      'rp_id' => 'example.com',
      'rp_name' => 'Test',
      'allowed_origins' => 'https://example.com',
      'attestation_policy' => 'none',
      'timeout' => '60000',
      'user_verification' => 'preferred',
      'require_resident_key' => FALSE,
      'allow_password_fallback' => TRUE,
      'challenge_ttl' => '999',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('600');
  }

  /**
   * Tests that a validation error does not persist config changes.
   */
  public function testValidationFailureDoesNotPersistChanges(): void {
    $user = $this->drupalCreateUser(['administer passkey forge']);
    $this->drupalLogin($user);

    $originalRpId = (string) $this->config('passkey_forge.settings')->get('rp_id');

    $this->drupalGet(self::SETTINGS_PATH);
    $this->submitForm([
      'enabled' => TRUE,
      'rp_id' => 'not a domain!!',   // Will fail validation.
      'rp_name' => 'Test',
      'allowed_origins' => 'https://example.com',
      'attestation_policy' => 'none',
      'timeout' => '60000',
      'user_verification' => 'preferred',
      'require_resident_key' => FALSE,
      'allow_password_fallback' => TRUE,
      'challenge_ttl' => '300',
    ], 'Save configuration');

    $this->assertSame($originalRpId, $this->config('passkey_forge.settings')->get('rp_id'));
  }

  // -------------------------------------------------------------------------
  // Menu / navigation
  // -------------------------------------------------------------------------

  /**
   * Tests that the settings page is linked from the Security admin section.
   */
  public function testSettingsPageLinkedFromSecurityMenu(): void {
    $user = $this->drupalCreateUser([
      'administer passkey forge',
      'access administration pages',
    ]);
    $this->drupalLogin($user);

    $this->drupalGet('/admin/config/security');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->linkByHrefExists(self::SETTINGS_PATH);
  }

}
