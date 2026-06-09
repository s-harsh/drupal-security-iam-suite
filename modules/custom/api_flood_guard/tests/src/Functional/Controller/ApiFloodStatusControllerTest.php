<?php

declare(strict_types=1);

namespace Drupal\Tests\api_flood_guard\Functional\Controller;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the API Flood Guard log and flood-state-data endpoints.
 *
 * @group api_flood_guard
 */
class ApiFloodStatusControllerTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['api_flood_guard', 'dblog'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Admin user with the administer permission.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $adminUser;

  /**
   * User without special permissions.
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
  // Log page — access control
  // -------------------------------------------------------------------------

  /**
   * Tests that the log page returns 200 for an admin user.
   */
  public function testLogPageLoadsForAdmin(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/log');
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that an anonymous user is denied access to the log page.
   */
  public function testAnonymousUserDeniedAccessToLogPage(): void {
    $this->drupalGet('/admin/config/security/api-flood-guard/log');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that an unprivileged authenticated user is denied the log page.
   */
  public function testUnprivilegedUserDeniedLogPage(): void {
    $this->drupalLogin($this->unprivilegedUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/log');
    $this->assertSession()->statusCodeEquals(403);
  }

  // -------------------------------------------------------------------------
  // Log page — content
  // -------------------------------------------------------------------------

  /**
   * Tests that a seeded api_flood_guard warning entry appears in the log table.
   */
  public function testSeededBlockEventAppearsInLog(): void {
    \Drupal::logger('api_flood_guard')->warning(
      'Test block event from @ip on @path.',
      ['@ip' => '1.2.3.4', '@path' => '/user/login'],
    );

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/log');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('1.2.3.4');
  }

  /**
   * Tests that the table header includes "Timestamp", "Severity", and "Message".
   */
  public function testLogPageTableHeadersArePresent(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/log');
    $this->assertSession()->pageTextContains('Timestamp');
    $this->assertSession()->pageTextContains('Severity');
    $this->assertSession()->pageTextContains('Message');
    $this->assertSession()->pageTextContains('Hostname');
  }

  /**
   * Tests that entries from a different log channel do NOT appear on this page.
   */
  public function testOtherChannelEntriesAreNotShown(): void {
    \Drupal::logger('system')->notice('System notice that should not appear in API Flood Guard log.');

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/log');
    $this->assertSession()->pageTextNotContains('System notice that should not appear in API Flood Guard log.');
  }

  /**
   * Tests that the empty-results message is shown when there are no log entries.
   */
  public function testEmptyLogPageShowsNoEntriesMessage(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/log');
    // When no entries exist the table caption / empty text should appear.
    $this->assertSession()->pageTextContains('No API Flood Guard block events found.');
  }

  /**
   * Tests that a severity filter query parameter is accepted without error.
   */
  public function testSeverityFilterQueryParamIsAccepted(): void {
    $this->drupalLogin($this->adminUser);
    // Severity 4 = WARNING.
    $this->drupalGet('/admin/config/security/api-flood-guard/log', ['query' => ['severity' => 4]]);
    $this->assertSession()->statusCodeEquals(200);
  }

  // -------------------------------------------------------------------------
  // Flood state JSON endpoint
  // -------------------------------------------------------------------------

  /**
   * Tests that the flood state data endpoint returns HTTP 200 for admins.
   */
  public function testFloodStateDataEndpointReturns200ForAdmin(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state/data');
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that the flood state data endpoint returns valid JSON.
   */
  public function testFloodStateDataEndpointReturnsValidJson(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state/data');
    $this->assertSession()->statusCodeEquals(200);

    $content = $this->getSession()->getPage()->getContent();
    $decoded = json_decode($content, TRUE);

    $this->assertIsArray($decoded);
    $this->assertArrayHasKey('entries', $decoded);
    $this->assertArrayHasKey('count', $decoded);
    $this->assertArrayHasKey('timestamp', $decoded);
  }

  /**
   * Tests that the count field matches the entries array length.
   */
  public function testFloodStateDataCountMatchesEntriesLength(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state/data');

    $decoded = json_decode($this->getSession()->getPage()->getContent(), TRUE);
    $this->assertSame($decoded['count'], count($decoded['entries']));
  }

  /**
   * Tests that flood state data endpoint returns seeded entries.
   */
  public function testFloodStateDataEndpointReturnsSeededEntries(): void {
    /** @var \Drupal\Core\Flood\FloodInterface $flood */
    $flood = \Drupal::service('flood');
    $flood->register('api_flood_guard.ip', 3600, '10.10.10.10');

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state/data');
    $decoded = json_decode($this->getSession()->getPage()->getContent(), TRUE);

    $this->assertGreaterThanOrEqual(1, $decoded['count']);
    $events = array_column($decoded['entries'], 'event');
    $this->assertContains('api_flood_guard.ip', $events);
  }

  /**
   * Tests that each entry in the JSON response has the expected fields.
   */
  public function testFloodStateDataEntriesHaveExpectedFields(): void {
    /** @var \Drupal\Core\Flood\FloodInterface $flood */
    $flood = \Drupal::service('flood');
    $flood->register('api_flood_guard.ip', 3600, '10.10.10.10');

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state/data');
    $decoded = json_decode($this->getSession()->getPage()->getContent(), TRUE);

    $this->assertNotEmpty($decoded['entries']);
    $firstEntry = $decoded['entries'][0];
    $this->assertArrayHasKey('fid', $firstEntry);
    $this->assertArrayHasKey('event', $firstEntry);
    $this->assertArrayHasKey('identifier', $firstEntry);
    $this->assertArrayHasKey('expiration', $firstEntry);
    $this->assertArrayHasKey('remaining', $firstEntry);
  }

  /**
   * Tests that the remaining field is a non-negative integer.
   */
  public function testFloodStateDataRemainingIsNonNegative(): void {
    /** @var \Drupal\Core\Flood\FloodInterface $flood */
    $flood = \Drupal::service('flood');
    $flood->register('api_flood_guard.ip', 3600, '10.10.10.10');

    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state/data');
    $decoded = json_decode($this->getSession()->getPage()->getContent(), TRUE);

    foreach ($decoded['entries'] as $entry) {
      $this->assertGreaterThanOrEqual(0, $entry['remaining']);
    }
  }

  /**
   * Tests that the anonymous user is denied the flood state data endpoint.
   */
  public function testAnonymousUserDeniedFloodStateDataEndpoint(): void {
    $this->drupalGet('/admin/config/security/api-flood-guard/flood-state/data');
    $this->assertSession()->statusCodeEquals(403);
  }

}
