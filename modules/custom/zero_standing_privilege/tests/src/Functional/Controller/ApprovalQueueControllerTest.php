<?php

declare(strict_types=1);

namespace Drupal\Tests\zero_standing_privilege\Functional\Controller;

use Drupal\Tests\BrowserTestBase;
use Drupal\zero_standing_privilege\Value\ElevationStatus;

/**
 * Functional tests for the ApprovalQueueController admin pages.
 *
 * @group zero_standing_privilege
 * @group functional
 */
final class ApprovalQueueControllerTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['zero_standing_privilege'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  // ---------------------------------------------------------------------------
  // Access control
  // ---------------------------------------------------------------------------

  /**
   * Anonymous users cannot access the approval queue.
   */
  public function testAnonymousCannotAccessQueue(): void {
    $this->drupalGet('/admin/config/security/zero-standing-privilege/queue');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * User without the approve permission cannot access the queue.
   */
  public function testUserWithoutPermissionCannotAccessQueue(): void {
    $user = $this->drupalCreateUser(['request privilege elevation']);
    $this->drupalLogin($user);
    $this->drupalGet('/admin/config/security/zero-standing-privilege/queue');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Approver with correct permission can access the approval queue.
   */
  public function testApproverCanAccessQueue(): void {
    $approver = $this->drupalCreateUser([
      'approve privilege elevation',
      'access administration pages',
    ]);
    $this->drupalLogin($approver);
    $this->drupalGet('/admin/config/security/zero-standing-privilege/queue');
    $this->assertSession()->statusCodeEquals(200);
  }

  // ---------------------------------------------------------------------------
  // Empty queue
  // ---------------------------------------------------------------------------

  /**
   * Queue page shows 'No pending' message when queue is empty.
   */
  public function testEmptyQueueShowsMessage(): void {
    $approver = $this->drupalCreateUser([
      'approve privilege elevation',
      'access administration pages',
    ]);
    $this->drupalLogin($approver);
    $this->drupalGet('/admin/config/security/zero-standing-privilege/queue');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('No pending elevation requests');
  }

  // ---------------------------------------------------------------------------
  // Pending request visibility
  // ---------------------------------------------------------------------------

  /**
   * A pending request appears in the approval queue table.
   */
  public function testPendingRequestAppearsInQueue(): void {
    $this->drupalCreateRole([], 'editor', 'Editor');
    $this->config('zero_standing_privilege.settings')
      ->set('require_approval', TRUE)
      ->set('allowed_target_roles', [])
      ->set('max_elevation_minutes', 240)
      ->set('notify_approvers_on_request', FALSE)
      ->save();

    // Create a requester and submit a request.
    $requester = $this->drupalCreateUser(['request privilege elevation']);
    \Drupal::service('zero_standing_privilege.privilege_manager')
      ->createRequest((int) $requester->id(), 'editor', 'Need to edit content for the marketing campaign', 60);

    // Log in as approver and view queue.
    $approver = $this->drupalCreateUser([
      'approve privilege elevation',
      'access administration pages',
    ]);
    $this->drupalLogin($approver);
    $this->drupalGet('/admin/config/security/zero-standing-privilege/queue');

    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('editor');
    $this->assertSession()->pageTextContains('Approve');
    $this->assertSession()->pageTextContains('Deny');
  }

  // ---------------------------------------------------------------------------
  // Active elevations page
  // ---------------------------------------------------------------------------

  /**
   * Admin can access the active elevations page.
   */
  public function testAdminCanAccessActiveElevationsPage(): void {
    $admin = $this->drupalCreateUser([
      'administer zero standing privilege',
      'access administration pages',
    ]);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/config/security/zero-standing-privilege/active');
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Active elevations table shows a live grant.
   */
  public function testActiveElevationsTableShowsLiveGrant(): void {
    $this->drupalCreateRole([], 'editor', 'Editor');
    $this->config('zero_standing_privilege.settings')
      ->set('require_approval', FALSE)
      ->set('allowed_target_roles', [])
      ->set('max_elevation_minutes', 240)
      ->set('notify_approvers_on_request', FALSE)
      ->set('notify_requester_on_grant', FALSE)
      ->save();

    $requester = $this->drupalCreateUser(['request privilege elevation']);
    \Drupal::service('zero_standing_privilege.privilege_manager')
      ->createRequest((int) $requester->id(), 'editor', 'Deployment task for next sprint release', 60);

    $admin = $this->drupalCreateUser([
      'administer zero standing privilege',
      'access administration pages',
    ]);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/config/security/zero-standing-privilege/active');

    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('editor');
  }

  // ---------------------------------------------------------------------------
  // Audit log page
  // ---------------------------------------------------------------------------

  /**
   * Admin can access the audit log page.
   */
  public function testAdminCanAccessAuditLogPage(): void {
    $admin = $this->drupalCreateUser([
      'administer zero standing privilege',
      'access administration pages',
    ]);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/config/security/zero-standing-privilege/audit');
    $this->assertSession()->statusCodeEquals(200);
  }

}
