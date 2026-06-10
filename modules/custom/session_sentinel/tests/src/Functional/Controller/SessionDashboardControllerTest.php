<?php

declare(strict_types=1);

namespace Drupal\Tests\session_sentinel\Functional\Controller;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the Session Sentinel admin dashboard controller.
 *
 * Verifies access control, page rendering, JSON data endpoint, and the
 * session kill action.
 *
 * @group session_sentinel
 */
final class SessionDashboardControllerTest extends BrowserTestBase {

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
   * Regular authenticated user without the admin permission.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $regularUser;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->adminUser   = $this->drupalCreateUser(['administer session sentinel']);
    $this->regularUser = $this->drupalCreateUser([]);
  }

  /**
   * Tests that the dashboard is accessible to users with the admin permission.
   */
  public function testDashboardIsAccessibleToAdmin(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/session-sentinel/dashboard');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('Session Sentinel');
  }

  /**
   * Tests that the dashboard is not accessible to regular authenticated users.
   */
  public function testDashboardIsForbiddenForRegularUsers(): void {
    $this->drupalLogin($this->regularUser);
    $this->drupalGet('/admin/config/security/session-sentinel/dashboard');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that the dashboard is not accessible to anonymous users.
   */
  public function testDashboardIsForbiddenForAnonymousUsers(): void {
    $this->drupalGet('/admin/config/security/session-sentinel/dashboard');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that the dashboard renders its table structure.
   */
  public function testDashboardRendersTableStructure(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/session-sentinel/dashboard');
    $this->assertSession()->statusCodeEquals(200);

    // The page should contain the expected table headers.
    $this->assertSession()->pageTextContains('User');
    $this->assertSession()->pageTextContains('IP Address');
    $this->assertSession()->pageTextContains('Last Active');
    $this->assertSession()->pageTextContains('Device Flagged');
  }

  /**
   * Tests that the dashboard shows "no active sessions" when table is empty.
   */
  public function testDashboardShowsEmptyMessageWithNoSessions(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/session-sentinel/dashboard');
    $this->assertSession()->statusCodeEquals(200);
    // The table empty text should be present when no session records exist.
    $this->assertSession()->pageTextContains('No active sessions found.');
  }

  /**
   * Tests that the JSON data endpoint returns valid JSON.
   */
  public function testDashboardDataEndpointReturnsJson(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/config/security/session-sentinel/dashboard/data', [
      'query' => ['_format' => 'json'],
    ]);
    $this->assertSession()->statusCodeEquals(200);

    $contentType = $this->getSession()->getResponseHeader('Content-Type');
    $this->assertStringContainsString('application/json', $contentType);

    $body = $this->getSession()->getPage()->getContent();
    $data = json_decode($body, TRUE);

    $this->assertIsArray($data);
    $this->assertArrayHasKey('sessions', $data);
    $this->assertArrayHasKey('total', $data);
    $this->assertArrayHasKey('flagged', $data);
    $this->assertArrayHasKey('timestamp', $data);
  }

  /**
   * Tests that the JSON data endpoint is forbidden for regular users.
   */
  public function testDashboardDataEndpointIsForbiddenForRegularUsers(): void {
    $this->drupalLogin($this->regularUser);
    $this->drupalGet('/admin/config/security/session-sentinel/dashboard/data', [
      'query' => ['_format' => 'json'],
    ]);
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that the kill endpoint rejects requests with an invalid CSRF token.
   */
  public function testKillSessionRejectsInvalidCsrfToken(): void {
    $this->drupalLogin($this->adminUser);

    $fakeHash = str_repeat('a', 64);
    $this->drupalGet('/admin/config/security/session-sentinel/kill/' . $fakeHash, [
      'query' => ['token' => 'invalid-csrf-token'],
    ]);

    // With an invalid CSRF token the controller should redirect back
    // to the dashboard with an error message.
    $this->assertSession()->addressEquals('/admin/config/security/session-sentinel/dashboard');
    $this->assertSession()->pageTextContains('Invalid CSRF token');
  }

  /**
   * Tests that the kill endpoint is not accessible to regular users.
   */
  public function testKillEndpointIsForbiddenForRegularUsers(): void {
    $this->drupalLogin($this->regularUser);
    $fakeHash = str_repeat('b', 64);
    $this->drupalGet('/admin/config/security/session-sentinel/kill/' . $fakeHash, [
      'query' => ['token' => 'any-token'],
    ]);
    $this->assertSession()->statusCodeEquals(403);
  }

}
