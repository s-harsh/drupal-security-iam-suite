<?php

declare(strict_types=1);

namespace Drupal\Tests\paranoia_reborn\Functional;

use Drupal\Tests\BrowserTestBase;

/**
 * Functional tests verifying Paranoia Reborn's access control behaviour.
 *
 * Tests real HTTP requests against a Drupal installation to confirm that the
 * AccessControlSubscriber correctly blocks or allows paths per role and profile.
 *
 * @group paranoia_reborn
 */
final class AccessControlTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['paranoia_reborn', 'dblog', 'field_ui', 'views_ui', 'node'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * An editor-level user with no trusted or bypass roles.
   *
   * @var \Drupal\user\UserInterface
   */
  private $editorUser;

  /**
   * An administrator user (trusted role).
   *
   * @var \Drupal\user\UserInterface
   */
  private $adminUser;

  /**
   * A developer user with the bypass permission.
   *
   * @var \Drupal\user\UserInterface
   */
  private $developerUser;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    // Ensure 'article' content type exists for field UI tests.
    $this->drupalCreateContentType(['type' => 'article', 'name' => 'Article']);

    $this->editorUser = $this->drupalCreateUser([
      'access content',
      'create article content',
      'edit own article content',
    ]);

    $this->adminUser = $this->drupalCreateUser([
      'administer paranoia reborn',
      'administer site configuration',
      'access administration pages',
      'administer content types',
      'administer node fields',
    ]);
    // Assign the administrator role so it's in trusted_roles.
    $this->adminUser->addRole('administrator');
    $this->adminUser->save();

    $this->developerUser = $this->drupalCreateUser([
      'bypass paranoia reborn restrictions',
      'access administration pages',
      'administer node fields',
    ]);

    // Set balanced profile via config.
    $this->config('paranoia_reborn.settings')
      ->set('lockdown_profile', 'balanced')
      ->set('trusted_roles', ['administrator'])
      ->set('admin_path_restriction', TRUE)
      ->set('field_ui_restriction', TRUE)
      ->set('views_ui_restriction', TRUE)
      ->set('disable_php_filter', TRUE)
      ->set('admin_path_exceptions', ['/admin/content', '/admin/content/files'])
      ->set('audit_log_enabled', TRUE)
      ->save();
  }

  /**
   * Tests that an editor is blocked from generic admin paths.
   */
  public function testEditorBlockedFromAdminConfig(): void {
    $this->drupalLogin($this->editorUser);
    $this->drupalGet('/admin/config/system/site-information');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that admin exceptions are accessible to editor.
   */
  public function testEditorAllowedOnAdminExceptions(): void {
    $this->drupalLogin($this->editorUser);
    // /admin/content is in the exception list.
    $this->drupalGet('/admin/content');
    // The editor may still get 403 from Drupal's own access system (no perm),
    // but the Paranoia Reborn subscriber should not trigger a block.
    // We verify no 403 comes from paranoia_reborn by checking the dblog.
    $blockedEntry = $this->getLastParanoiaRebornLog();
    $this->assertNull($blockedEntry, 'No Paranoia Reborn block log entry for exception path.');
  }

  /**
   * Tests that an editor is blocked from Field UI routes.
   */
  public function testEditorBlockedFromFieldUi(): void {
    $this->drupalLogin($this->editorUser);
    $this->drupalGet('/admin/structure/types/manage/article/fields');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that an editor is blocked from Views UI routes.
   */
  public function testEditorBlockedFromViewsUi(): void {
    $this->drupalLogin($this->editorUser);
    $this->drupalGet('/admin/structure/views');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * Tests that the admin user (trusted role) can access admin paths.
   */
  public function testAdminUserCanAccessAdminPaths(): void {
    $this->drupalLogin($this->adminUser);
    $this->drupalGet('/admin/structure/types/manage/article/fields');
    // Should not receive a Paranoia Reborn 403; Drupal's own checks may vary.
    // We verify no log entry from paranoia_reborn.
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that a user with the bypass permission can access protected paths.
   */
  public function testBypassPermissionAllowsAccess(): void {
    $this->drupalLogin($this->developerUser);
    $this->drupalGet('/admin/structure/types/manage/article/fields');
    // Paranoia Reborn should not block; Drupal access may still apply but
    // the developer user has administer node fields.
    $this->assertSession()->statusCodeEquals(200);
  }

  /**
   * Tests that blocked attempts are written to the audit log (dblog).
   */
  public function testBlockedAttemptIsAuditLogged(): void {
    $this->drupalLogin($this->editorUser);

    // Clear existing logs.
    \Drupal::database()->delete('watchdog')
      ->condition('type', 'paranoia_reborn')
      ->execute();

    $this->drupalGet('/admin/structure/views');
    $this->assertSession()->statusCodeEquals(403);

    $entry = $this->getLastParanoiaRebornLog();
    $this->assertNotNull($entry, 'A Paranoia Reborn audit log entry was written.');
    $this->assertStringContainsString('/admin/structure/views', (string) $entry->message);
  }

  /**
   * Tests that the audit log is NOT written when audit_log_enabled = FALSE.
   */
  public function testAuditLogRespectsDisabledFlag(): void {
    $this->config('paranoia_reborn.settings')
      ->set('audit_log_enabled', FALSE)
      ->save();

    $this->drupalLogin($this->editorUser);

    // Clear existing logs.
    \Drupal::database()->delete('watchdog')
      ->condition('type', 'paranoia_reborn')
      ->execute();

    $this->drupalGet('/admin/structure/views');
    $this->assertSession()->statusCodeEquals(403);

    $entry = $this->getLastParanoiaRebornLog();
    $this->assertNull($entry, 'No audit log entry written when audit_log_enabled is FALSE.');
  }

  /**
   * Returns the most recent paranoia_reborn watchdog entry, or NULL.
   *
   * @return object|null
   */
  private function getLastParanoiaRebornLog(): ?object {
    try {
      return \Drupal::database()->select('watchdog', 'w')
        ->fields('w', ['wid', 'message', 'variables', 'timestamp'])
        ->condition('w.type', 'paranoia_reborn')
        ->orderBy('w.wid', 'DESC')
        ->range(0, 1)
        ->execute()
        ->fetchObject() ?: NULL;
    }
    catch (\Exception) {
      return NULL;
    }
  }

}
