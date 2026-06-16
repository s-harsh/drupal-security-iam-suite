<?php

declare(strict_types=1);

namespace Drupal\Tests\zero_standing_privilege\Functional\Form;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests for the ElevationRequestForm.
 *
 * @group zero_standing_privilege
 * @group functional
 */
final class ElevationRequestFormTest extends BrowserTestBase {

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
   * Anonymous users are redirected away from the request form.
   */
  public function testAnonymousCannotAccessForm(): void {
    $this->drupalGet('/zsp/request');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * An authenticated user with the correct permission can access the form.
   */
  public function testAuthenticatedUserWithPermissionCanAccessForm(): void {
    $user = $this->drupalCreateUser(['request privilege elevation']);
    $this->drupalLogin($user);
    $this->drupalGet('/zsp/request');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->elementExists('css', 'form#zsp-elevation-request-form, form[id="zsp-elevation-request-form"]');
  }

  /**
   * An authenticated user without permission receives 403.
   */
  public function testAuthenticatedUserWithoutPermissionGets403(): void {
    $user = $this->drupalCreateUser();
    $this->drupalLogin($user);
    $this->drupalGet('/zsp/request');
    $this->assertSession()->statusCodeEquals(403);
  }

  // ---------------------------------------------------------------------------
  // Form validation
  // ---------------------------------------------------------------------------

  /**
   * Submitting an empty reason is rejected with a validation error.
   */
  public function testEmptyReasonIsRejected(): void {
    // Create a role to request.
    $this->drupalCreateRole([], 'editor', 'Editor');
    $this->config('zero_standing_privilege.settings')
      ->set('allowed_target_roles', [])
      ->save();

    $user = $this->drupalCreateUser(['request privilege elevation']);
    $this->drupalLogin($user);
    $this->drupalGet('/zsp/request');

    $this->submitForm([
      'target_role'      => 'editor',
      'duration_minutes' => 60,
      'reason'           => '',
    ], 'Submit request');

    $this->assertSession()->pageTextContains('field is required');
  }

  /**
   * Submitting a too-short reason is rejected.
   */
  public function testShortReasonIsRejected(): void {
    $this->drupalCreateRole([], 'editor', 'Editor');
    $user = $this->drupalCreateUser(['request privilege elevation']);
    $this->drupalLogin($user);
    $this->drupalGet('/zsp/request');

    $this->submitForm([
      'target_role'      => 'editor',
      'duration_minutes' => 60,
      'reason'           => 'Too short',
    ], 'Submit request');

    $this->assertSession()->pageTextContains('at least 10 characters');
  }

  /**
   * Submitting a duration exceeding the configured max is rejected.
   */
  public function testDurationExceedingMaxIsRejected(): void {
    $this->config('zero_standing_privilege.settings')
      ->set('max_elevation_minutes', 60)
      ->save();

    $this->drupalCreateRole([], 'editor', 'Editor');
    $user = $this->drupalCreateUser(['request privilege elevation']);
    $this->drupalLogin($user);
    $this->drupalGet('/zsp/request');

    $this->submitForm([
      'target_role'      => 'editor',
      'duration_minutes' => 999,
      'reason'           => 'I need this role for a critical deployment task',
    ], 'Submit request');

    $this->assertSession()->pageTextContains('cannot exceed');
  }

  // ---------------------------------------------------------------------------
  // Successful submission
  // ---------------------------------------------------------------------------

  /**
   * A valid submission creates a pending elevation request and redirects.
   */
  public function testValidSubmissionCreatesPendingRequest(): void {
    $this->drupalCreateRole([], 'editor', 'Editor');
    $this->config('zero_standing_privilege.settings')
      ->set('require_approval', TRUE)
      ->set('allowed_target_roles', [])
      ->set('max_elevation_minutes', 240)
      ->set('default_elevation_minutes', 60)
      ->save();

    $user = $this->drupalCreateUser(['request privilege elevation']);
    $this->drupalLogin($user);
    $this->drupalGet('/zsp/request');

    $this->submitForm([
      'target_role'      => 'editor',
      'duration_minutes' => 60,
      'reason'           => 'I need to publish several blog posts for the upcoming launch',
    ], 'Submit request');

    $this->assertSession()->pageTextContains('awaiting approval');

    // Verify entity was created.
    $ids = \Drupal::entityTypeManager()->getStorage('elevation_request')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('requester_uid', $user->id())
      ->condition('status', 'pending')
      ->execute();

    $this->assertCount(1, $ids, 'One pending elevation request should exist after submission.');
  }

  /**
   * A duplicate pending request for the same role is blocked.
   */
  public function testDuplicatePendingRequestIsBlocked(): void {
    $this->drupalCreateRole([], 'editor', 'Editor');
    $this->config('zero_standing_privilege.settings')
      ->set('require_approval', TRUE)
      ->set('allowed_target_roles', [])
      ->set('max_elevation_minutes', 240)
      ->save();

    $user = $this->drupalCreateUser(['request privilege elevation']);
    $this->drupalLogin($user);

    // First submission.
    $this->drupalGet('/zsp/request');
    $this->submitForm([
      'target_role'      => 'editor',
      'duration_minutes' => 60,
      'reason'           => 'First valid justification for the editor role here',
    ], 'Submit request');

    // Second submission (duplicate).
    $this->drupalGet('/zsp/request');
    $this->submitForm([
      'target_role'      => 'editor',
      'duration_minutes' => 60,
      'reason'           => 'Same role again, should be blocked by validation',
    ], 'Submit request');

    $this->assertSession()->pageTextContains('already have a pending elevation request');
  }

}
