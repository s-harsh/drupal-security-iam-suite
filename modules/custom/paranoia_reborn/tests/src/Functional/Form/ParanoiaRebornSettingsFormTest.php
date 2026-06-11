<?php

declare(strict_types=1);

namespace Drupal\Tests\paranoia_reborn\Functional\Form;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for ParanoiaRebornSettingsForm.
 *
 * @group paranoia_reborn
 */
final class ParanoiaRebornSettingsFormTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['paranoia_reborn', 'dblog'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * An admin user with full configuration rights.
   *
   * @var \Drupal\user\UserInterface
   */
  private $adminUser;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->adminUser = $this->drupalCreateUser([
      'administer paranoia reborn',
      'administer site configuration',
      'access administration pages',
    ]);
  }

  /**
   * Tests that the settings form is accessible only to privileged users.
   */
  public function testFormAccessControl(): void {
    // Anonymous access is denied.
    $this->drupalGet('/admin/config/security/paranoia-reborn');
    $this->assertSession()->statusCodeEquals(403);

    // Admin user can access the form.
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/paranoia-reborn');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->elementExists('css', 'form#paranoia-reborn-settings-form');
  }

  /**
   * Tests that the form renders all expected field groups.
   */
  public function testFormRendersAllSections(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/paranoia-reborn');

    $this->assertSession()->pageTextContains('Lockdown Profile');
    $this->assertSession()->pageTextContains('Role Configuration');
    $this->assertSession()->pageTextContains('Admin Path Exceptions');
    $this->assertSession()->pageTextContains('Custom Protection Toggles');
    $this->assertSession()->pageTextContains('Audit Logging');
  }

  /**
   * Tests saving the balanced profile stores the correct config values.
   */
  public function testSaveBalancedProfile(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/paranoia-reborn');

    $this->submitForm(
      [
        'lockdown_profile'   => 'balanced',
        'audit_log_enabled'  => TRUE,
        'admin_path_exceptions' => "/admin/content\n/admin/content/files",
      ],
      'Save configuration'
    );

    $this->assertSession()->pageTextContains('The configuration options have been saved.');

    $config = $this->config('paranoia_reborn.settings');
    $this->assertSame('balanced', $config->get('lockdown_profile'));
    $this->assertTrue((bool) $config->get('audit_log_enabled'));
    $this->assertContains('/admin/content', (array) $config->get('admin_path_exceptions'));
  }

  /**
   * Tests saving the strict profile forces all protections on.
   */
  public function testSaveStrictProfileForcesAllProtections(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/paranoia-reborn');

    $this->submitForm(
      [
        'lockdown_profile'          => 'strict',
        'admin_path_restriction'    => FALSE,  // Should be overridden to TRUE.
        'field_ui_restriction'      => FALSE,  // Should be overridden to TRUE.
        'views_ui_restriction'      => FALSE,  // Should be overridden to TRUE.
        'disable_php_filter'        => FALSE,  // Should be overridden to TRUE.
        'audit_log_enabled'         => TRUE,
        'admin_path_exceptions'     => '',
      ],
      'Save configuration'
    );

    $this->assertSession()->pageTextContains('The configuration options have been saved.');

    $config = $this->config('paranoia_reborn.settings');
    $this->assertSame('strict', $config->get('lockdown_profile'));
    $this->assertTrue((bool) $config->get('admin_path_restriction'));
    $this->assertTrue((bool) $config->get('field_ui_restriction'));
    $this->assertTrue((bool) $config->get('views_ui_restriction'));
    $this->assertTrue((bool) $config->get('disable_php_filter'));
  }

  /**
   * Tests that invalid admin path exceptions (no leading slash) are rejected.
   */
  public function testValidationRejectsInvalidExceptions(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/paranoia-reborn');

    $this->submitForm(
      [
        'lockdown_profile'       => 'balanced',
        'admin_path_exceptions'  => "admin/content\nadmin/structure",  // Missing leading /.
        'audit_log_enabled'      => TRUE,
      ],
      'Save configuration'
    );

    $this->assertSession()->pageTextContains('Each admin path exception must start with /.');
  }

  /**
   * Tests saving the custom profile persists individual toggles correctly.
   */
  public function testSaveCustomProfile(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/paranoia-reborn');

    $this->submitForm(
      [
        'lockdown_profile'       => 'custom',
        'admin_path_restriction' => TRUE,
        'disable_php_filter'     => TRUE,
        'field_ui_restriction'   => FALSE,
        'views_ui_restriction'   => TRUE,
        'audit_log_enabled'      => FALSE,
        'admin_path_exceptions'  => '/admin/content',
      ],
      'Save configuration'
    );

    $this->assertSession()->pageTextContains('The configuration options have been saved.');

    $config = $this->config('paranoia_reborn.settings');
    $this->assertSame('custom', $config->get('lockdown_profile'));
    $this->assertTrue((bool) $config->get('admin_path_restriction'));
    $this->assertFalse((bool) $config->get('field_ui_restriction'));
    $this->assertTrue((bool) $config->get('views_ui_restriction'));
    $this->assertFalse((bool) $config->get('audit_log_enabled'));
  }

}
