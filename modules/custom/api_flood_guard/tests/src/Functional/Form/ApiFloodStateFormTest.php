<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Functional\Form;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the API Flood Guard flood state dashboard.
 *
 * @group api_flood_guard
 */
class ApiFloodStateFormTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['api_flood_guard', 'dblog'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Admin user.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $adminUser;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->adminUser = $this->drupalCreateUser(['administer api flood guard']);
  }

  // -------------------------------------------------------------------------
  // Access control
  // -------------------------------------------------------------------------

  /**
   * Tests that the flood state dashboard loads for an admin user.
   */
  public function testDashboardLoadsForAdminUser(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that an anonymous user is denied access to the flood state page.
   */
  public function testAnonymousUserCannotAccessFloodState(): void {
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');
    $this->assertSession()->statusCodeEquals(403);
  }

  // -------------------------------------------------------------------------
  // Empty state
  // -------------------------------------------------------------------------

  /**
   * Tests that the empty state message is shown when there are no flood entries.
   */
  public function testEmptyStateLabelShownWithNoEntries(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('No active API flood entries.');
  }

  // -------------------------------------------------------------------------
  // Seeded entries appear in table
  // -------------------------------------------------------------------------

  /**
   * Tests that seeded IP flood entries appear in the table.
   */
  public function testSeededIpFloodEntryAppearsInTable(): void {
    /** @var \Drupal\Core\Flood\FloodInterface $flood */
    $flood = \Drupal::service('flood');
    $flood->register('api_flood_guard.ip', 3600, '10.20.30.40');

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('api_flood_guard.ip');
    $this->assertSession()->pageTextContains('10.20.30.40');
  }

  /**
   * Tests that seeded user flood entries appear in the table.
   */
  public function testSeededUserFloodEntryAppearsInTable(): void {
    /** @var \Drupal\Core\Flood\FloodInterface $flood */
    $flood = \Drupal::service('flood');
    $userHash = hash('sha256', 'testuser');
    $flood->register('api_flood_guard.user', 900, $userHash);

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');
    $this->assertSession()->pageTextContains('api_flood_guard.user');
  }

  // -------------------------------------------------------------------------
  // Bulk clear operations
  // -------------------------------------------------------------------------

  /**
   * Tests that "Clear all" removes all api_flood_guard.* flood entries.
   */
  public function testClearAllButtonRemovesAllEntries(): void {
    /** @var \Drupal\Core\Flood\FloodInterface $flood */
    $flood = \Drupal::service('flood');
    $flood->register('api_flood_guard.ip', 3600, '10.20.30.40');
    $flood->register('api_flood_guard.user', 900, hash('sha256', 'testuser'));

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');

    $this->submitForm([], 'Clear all API flood entries');
    $this->assertSession()->pageTextContains('All API Flood Guard flood entries have been cleared.');

    // Reload and check the empty state is shown.
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');
    $this->assertSession()->pageTextContains('No active API flood entries.');
  }

  /**
   * Tests that "Clear all IP flood entries" removes only IP-namespace entries.
   */
  public function testClearAllIpEntriesLeavesUserEntriesIntact(): void {
    /** @var \Drupal\Core\Flood\FloodInterface $flood */
    $flood = \Drupal::service('flood');
    $flood->register('api_flood_guard.ip', 3600, '10.20.30.40');
    $flood->register('api_flood_guard.user', 900, hash('sha256', 'testuser'));

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');

    $this->submitForm([], 'Clear all IP flood entries');
    $this->assertSession()->pageTextContains('All API Flood Guard IP flood entries have been cleared.');

    // The user entry should still be visible.
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');
    $this->assertSession()->pageTextContains('api_flood_guard.user');
  }

  /**
   * Tests that "Clear all username flood entries" removes only user-namespace entries.
   */
  public function testClearAllUserEntriesLeavesIpEntriesIntact(): void {
    /** @var \Drupal\Core\Flood\FloodInterface $flood */
    $flood = \Drupal::service('flood');
    $flood->register('api_flood_guard.ip', 3600, '10.20.30.40');
    $flood->register('api_flood_guard.user', 900, hash('sha256', 'testuser'));

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');

    $this->submitForm([], 'Clear all username flood entries');
    $this->assertSession()->pageTextContains('All API Flood Guard username flood entries have been cleared.');

    // The IP entry should still be visible.
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');
    $this->assertSession()->pageTextContains('api_flood_guard.ip');
  }

  /**
   * Tests that status messages are shown after successful bulk clear.
   */
  public function testStatusMessageAppearsAfterClearAll(): void {
    /** @var \Drupal\Core\Flood\FloodInterface $flood */
    $flood = \Drupal::service('flood');
    $flood->register('api_flood_guard.ip', 3600, '1.2.3.4');

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');

    $this->submitForm([], 'Clear all API flood entries');
    $this->assertSession()->pageTextContains('All API Flood Guard flood entries have been cleared.');
  }

  // -------------------------------------------------------------------------
  // Dashboard auto-refresh library
  // -------------------------------------------------------------------------

  /**
   * Tests that the flood state refresh library is attached to the page.
   */
  public function testFloodStateRefreshLibraryIsAttached(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state');
    // The page response should include the library's JS file reference.
    $this->assertSession()->responseContains('flood-state-refresh');
  }

}
