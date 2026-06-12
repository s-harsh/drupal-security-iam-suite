<?php

declare(strict_types=1);

namespace Drupal\Tests\sbom_sentinel\Functional\Controller;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the SBOM Sentinel report and export controllers.
 *
 * Exercises the full HTTP request cycle including access control, page
 * rendering, and response headers for the JSON/XML export endpoints.
 *
 * @group sbom_sentinel
 */
final class SbomReportControllerTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['sbom_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * The report page path.
   */
  private const REPORT_PATH = '/admin/reports/sbom-sentinel';

  /**
   * The JSON export path.
   */
  private const EXPORT_JSON_PATH = '/admin/reports/sbom-sentinel/export/json';

  /**
   * The XML export path.
   */
  private const EXPORT_XML_PATH = '/admin/reports/sbom-sentinel/export/xml';

  /**
   * The settings page path.
   */
  private const SETTINGS_PATH = '/admin/config/security/sbom-sentinel';

  // -------------------------------------------------------------------------
  // Access control — report page
  // -------------------------------------------------------------------------

  /**
   * Tests that anonymous users are redirected from the report page.
   */
  public function testAnonymousUserCannotAccessReportPage(): void {
    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->addressNotEquals(self::REPORT_PATH);
  }

  /**
   * Tests that a user without permission receives HTTP 403 on the report page.
   */
  public function testUserWithoutPermissionCannotAccessReportPage(): void {
    $user = $this->drupalCreateUser(['access administration pages']);
    $this->drupalLogin($user);

    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that a user with 'view sbom sentinel report' can access the page.
   */
  public function testUserWithViewPermissionCanAccessReportPage(): void {
    $user = $this->drupalCreateUser(['view sbom sentinel report']);
    $this->drupalLogin($user);

    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that a site admin can access the report page.
   */
  public function testAdministratorCanAccessReportPage(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->statusCodeEquals(200);
  }

  // -------------------------------------------------------------------------
  // Report page rendering
  // -------------------------------------------------------------------------

  /**
   * Tests that the report page contains the expected title.
   */
  public function testReportPageHasCorrectTitle(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->titleContains('SBOM Sentinel');
  }

  /**
   * Tests that the report page renders a table element.
   */
  public function testReportPageRendersTable(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->elementExists('css', 'table');
  }

  /**
   * Tests that the report page contains export links.
   */
  public function testReportPageContainsJsonExportLink(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->linkByHrefExists(self::EXPORT_JSON_PATH);
  }

  /**
   * Tests that the report page contains an XML export link.
   */
  public function testReportPageContainsXmlExportLink(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->linkByHrefExists(self::EXPORT_XML_PATH);
  }

  /**
   * Tests that the report page table includes the expected column headers.
   */
  public function testReportPageTableHasPackageColumn(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->pageTextContains('Package');
  }

  /**
   * Tests that the report page table includes the CVE Count column.
   */
  public function testReportPageTableHasCveCountColumn(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->pageTextContains('CVE Count');
  }

  /**
   * Tests that the report page table includes the NIS2 Risk column.
   */
  public function testReportPageTableHasNisRiskColumn(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet(self::REPORT_PATH);
    $this->assertSession()->pageTextContains('NIS2 Risk');
  }

  // -------------------------------------------------------------------------
  // Access control — export endpoints
  // -------------------------------------------------------------------------

  /**
   * Tests that anonymous users cannot access the JSON export endpoint.
   */
  public function testAnonymousUserCannotAccessJsonExport(): void {
    $this->drupalGet(self::EXPORT_JSON_PATH);
    $this->assertSession()->addressNotEquals(self::EXPORT_JSON_PATH);
  }

  /**
   * Tests that a user with 'export sbom sentinel' can access the JSON export.
   */
  public function testUserWithExportPermissionCanAccessJsonExport(): void {
    $user = $this->drupalCreateUser(['export sbom sentinel']);
    $this->drupalLogin($user);

    $this->drupalGet(self::EXPORT_JSON_PATH);
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that a user with 'export sbom sentinel' can access the XML export.
   */
  public function testUserWithExportPermissionCanAccessXmlExport(): void {
    $user = $this->drupalCreateUser(['export sbom sentinel']);
    $this->drupalLogin($user);

    $this->drupalGet(self::EXPORT_XML_PATH);
    $this->assertSession()->statusCodeEquals(200);
  }

  // -------------------------------------------------------------------------
  // Settings page
  // -------------------------------------------------------------------------

  /**
   * Tests that the settings page loads with HTTP 200 for an admin.
   */
  public function testSettingsPageLoadsForAdmin(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that the settings page title contains 'SBOM Sentinel'.
   */
  public function testSettingsPageTitleContainsSbomSentinel(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet(self::SETTINGS_PATH);
    $this->assertSession()->titleContains('SBOM Sentinel');
  }

  /**
   * Tests that all expected form fields exist on the settings page.
   */
  public function testSettingsPageRendersAllFields(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->assertSession()->fieldExists('enabled');
    $this->assertSession()->fieldExists('composer_lock_path');
    $this->assertSession()->fieldExists('osv_api_base_url');
    $this->assertSession()->fieldExists('http_timeout');
    $this->assertSession()->fieldExists('scan_cache_ttl');
    $this->assertSession()->fieldExists('cron_enabled');
    $this->assertSession()->fieldExists('email_report_enabled');
  }

  /**
   * Tests that saving valid settings shows the confirmation message.
   */
  public function testSavingValidSettingsShowsConfirmation(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'              => TRUE,
      'composer_lock_path'   => '../composer.lock',
      'osv_api_base_url'     => 'https://api.osv.dev/v1',
      'http_timeout'         => '10',
      'scan_cache_ttl'       => '3600',
      'cron_enabled'         => TRUE,
      'email_report_enabled' => FALSE,
      'email_recipient'      => '',
    ], 'Save configuration');

    $this->assertSession()->statusMessageContains('The configuration options have been saved.');
  }

  /**
   * Tests that an invalid HTTP timeout value fails validation.
   */
  public function testInvalidHttpTimeoutFailsValidation(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'              => TRUE,
      'composer_lock_path'   => '../composer.lock',
      'osv_api_base_url'     => 'https://api.osv.dev/v1',
      'http_timeout'         => '0',
      'scan_cache_ttl'       => '3600',
      'cron_enabled'         => FALSE,
      'email_report_enabled' => FALSE,
      'email_recipient'      => '',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('HTTP timeout must be an integer between 1 and 60');
  }

  /**
   * Tests that a relative OSV API URL fails validation.
   */
  public function testRelativeOsvApiUrlFailsValidation(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'              => TRUE,
      'composer_lock_path'   => '../composer.lock',
      'osv_api_base_url'     => '/relative/path',
      'http_timeout'         => '10',
      'scan_cache_ttl'       => '3600',
      'cron_enabled'         => FALSE,
      'email_report_enabled' => FALSE,
      'email_recipient'      => '',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('OSV API base URL must be a valid absolute URL');
  }

  /**
   * Tests that an invalid email recipient fails validation.
   */
  public function testInvalidEmailRecipientFailsValidation(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);
    $this->drupalGet(self::SETTINGS_PATH);

    $this->submitForm([
      'enabled'              => TRUE,
      'composer_lock_path'   => '../composer.lock',
      'osv_api_base_url'     => 'https://api.osv.dev/v1',
      'http_timeout'         => '10',
      'scan_cache_ttl'       => '3600',
      'cron_enabled'         => TRUE,
      'email_report_enabled' => TRUE,
      'email_recipient'      => 'not-an-email',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('email recipient address is not a valid email address');
  }

  /**
   * Tests that the report page is linked from the admin reports menu.
   */
  public function testReportPageIsLinkedFromAdminReports(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/reports');
    $this->assertSession()->linkByHrefExists(self::REPORT_PATH);
  }

  /**
   * Tests that the settings page is linked from admin config security.
   */
  public function testSettingsPageIsLinkedFromAdminConfigSecurity(): void {
    $admin = $this->drupalCreateUser([], NULL, TRUE);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/config/security');
    $this->assertSession()->linkByHrefExists(self::SETTINGS_PATH);
  }

}
