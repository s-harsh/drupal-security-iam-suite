<?php

declare(strict_types=1);

namespace Drupal\Tests\paranoia_reborn\Unit\Service;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\paranoia_reborn\Service\PathRestrictor;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for PathRestrictor.
 *
 * @coversDefaultClass \Drupal\paranoia_reborn\Service\PathRestrictor
 * @group paranoia_reborn
 */
final class PathRestrictorTest extends TestCase {

  /**
   * A mock config object pre-loaded with balanced-profile defaults.
   */
  private Config&MockObject $config;

  /**
   * A mock config factory.
   */
  private ConfigFactoryInterface&MockObject $configFactory;

  /**
   * A mock logger.
   */
  private LoggerInterface&MockObject $logger;

  /**
   * A mock current user (unused in isBlocked, but required by constructor).
   */
  private AccountInterface&MockObject $currentUser;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->config = $this->createMock(Config::class);
    $this->configFactory = $this->createMock(ConfigFactoryInterface::class);
    $this->logger = $this->createMock(LoggerInterface::class);
    $this->currentUser = $this->createMock(AccountInterface::class);

    $this->configFactory
      ->method('get')
      ->with('paranoia_reborn.settings')
      ->willReturn($this->config);
  }

  /**
   * Builds a PathRestrictor with the current mocks.
   */
  private function buildService(): PathRestrictor {
    return new PathRestrictor(
      $this->configFactory,
      $this->currentUser,
      $this->logger,
    );
  }

  /**
   * Returns a balanced-profile config array.
   *
   * @return array<string, mixed>
   */
  private function balancedConfig(): array {
    return [
      'lockdown_profile'          => 'balanced',
      'trusted_roles'             => ['administrator'],
      'admin_path_allowlist_roles' => [],
      'admin_path_restriction'    => TRUE,
      'disable_php_filter'        => TRUE,
      'field_ui_restriction'      => TRUE,
      'views_ui_restriction'      => TRUE,
      'admin_path_exceptions'     => ['/admin/content', '/admin/content/files'],
      'audit_log_enabled'         => TRUE,
    ];
  }

  /**
   * @covers ::isAdminPath
   */
  public function testIsAdminPathDetectsAdminRoot(): void {
    $service = $this->buildService();
    self::assertTrue($service->isAdminPath('/admin'));
    self::assertTrue($service->isAdminPath('/admin/structure'));
    self::assertFalse($service->isAdminPath('/node/1'));
    self::assertFalse($service->isAdminPath('/'));
  }

  /**
   * @covers ::isFieldUiPath
   */
  public function testIsFieldUiPathDetectsFieldRoutes(): void {
    $service = $this->buildService();

    self::assertTrue($service->isFieldUiPath('/admin/structure/types/manage/article/fields'));
    self::assertTrue($service->isFieldUiPath('/admin/structure/types/manage/page/form-display'));
    self::assertTrue($service->isFieldUiPath('/admin/structure/types/manage/page/display'));
    self::assertTrue($service->isFieldUiPath('/admin/structure/taxonomy/manage/tags/fields'));
    self::assertFalse($service->isFieldUiPath('/admin/structure/types'));
    self::assertFalse($service->isFieldUiPath('/admin/content'));
  }

  /**
   * @covers ::isViewsUiPath
   */
  public function testIsViewsUiPathDetectsViewsRoutes(): void {
    $service = $this->buildService();

    self::assertTrue($service->isViewsUiPath('/admin/structure/views'));
    self::assertTrue($service->isViewsUiPath('/admin/structure/views/add'));
    self::assertFalse($service->isViewsUiPath('/admin/structure/types'));
  }

  /**
   * @covers ::isBlocked
   *
   * UID 1 should never be blocked.
   */
  public function testUid1NeverBlocked(): void {
    $this->config->method('get')->willReturn($this->balancedConfig());

    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn('1');
    $account->method('isAnonymous')->willReturn(FALSE);
    $account->method('hasPermission')->willReturn(FALSE);
    $account->method('getRoles')->willReturn(['administrator']);

    $service = $this->buildService();

    self::assertFalse($service->isBlocked('/admin/structure/types/manage/article/fields', $account));
    self::assertFalse($service->isBlocked('/admin/structure/views', $account));
    self::assertFalse($service->isBlocked('/admin/config', $account));
  }

  /**
   * @covers ::isBlocked
   *
   * Anonymous user should be blocked from /admin paths.
   */
  public function testAnonymousBlockedFromAdminPaths(): void {
    $this->config->method('get')->willReturn($this->balancedConfig());

    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn('0');
    $account->method('isAnonymous')->willReturn(TRUE);

    $service = $this->buildService();

    self::assertTrue($service->isBlocked('/admin/structure', $account));
    self::assertTrue($service->isBlocked('/admin/structure/types/manage/article/fields', $account));
  }

  /**
   * @covers ::isBlocked
   *
   * Authenticated editor (no trusted role) should be blocked from admin paths
   * except the configured exceptions.
   */
  public function testEditorBlockedFromAdminButNotExceptions(): void {
    $configData = $this->balancedConfig();
    $this->config->method('get')->willReturnCallback(
      function (string $key = NULL) use ($configData) {
        if ($key === NULL) {
          return $configData;
        }
        return $configData[$key] ?? NULL;
      }
    );

    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn('42');
    $account->method('isAnonymous')->willReturn(FALSE);
    $account->method('hasPermission')->willReturn(FALSE);
    $account->method('getRoles')->willReturn(['authenticated', 'editor']);

    $service = $this->buildService();

    // Blocked admin path.
    self::assertTrue($service->isBlocked('/admin/config/system/site-information', $account));

    // Allowed exception.
    self::assertFalse($service->isBlocked('/admin/content', $account));
    self::assertFalse($service->isBlocked('/admin/content/files', $account));
  }

  /**
   * @covers ::isBlocked
   *
   * Administrator role is in trusted_roles and should bypass all restrictions.
   */
  public function testAdminRoleBypassesRestrictions(): void {
    $configData = $this->balancedConfig();
    $this->config->method('get')->willReturnCallback(
      function (string $key = NULL) use ($configData) {
        return $key === NULL ? $configData : ($configData[$key] ?? NULL);
      }
    );

    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn('5');
    $account->method('isAnonymous')->willReturn(FALSE);
    $account->method('hasPermission')->willReturn(FALSE);
    $account->method('getRoles')->willReturn(['authenticated', 'administrator']);

    $service = $this->buildService();

    self::assertFalse($service->isBlocked('/admin/structure/types/manage/article/fields', $account));
    self::assertFalse($service->isBlocked('/admin/structure/views', $account));
    self::assertFalse($service->isBlocked('/admin/config', $account));
  }

  /**
   * @covers ::isBlocked
   *
   * User with 'bypass paranoia reborn restrictions' permission should bypass.
   */
  public function testBypassPermissionSkipsAllChecks(): void {
    $configData = $this->balancedConfig();
    $this->config->method('get')->willReturnCallback(
      function (string $key = NULL) use ($configData) {
        return $key === NULL ? $configData : ($configData[$key] ?? NULL);
      }
    );

    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn('99');
    $account->method('isAnonymous')->willReturn(FALSE);
    $account->method('hasPermission')
      ->with('bypass paranoia reborn restrictions')
      ->willReturn(TRUE);
    $account->method('getRoles')->willReturn(['authenticated']);

    $service = $this->buildService();

    self::assertFalse($service->isBlocked('/admin/structure/views', $account));
  }

  /**
   * @covers ::isBlocked
   *
   * Field UI paths should be blocked for editors in balanced profile.
   */
  public function testEditorBlockedFromFieldUi(): void {
    $configData = $this->balancedConfig();
    $this->config->method('get')->willReturnCallback(
      function (string $key = NULL) use ($configData) {
        return $key === NULL ? $configData : ($configData[$key] ?? NULL);
      }
    );

    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn('42');
    $account->method('isAnonymous')->willReturn(FALSE);
    $account->method('hasPermission')->willReturn(FALSE);
    $account->method('getRoles')->willReturn(['authenticated', 'editor']);

    $service = $this->buildService();

    self::assertTrue($service->isBlocked('/admin/structure/types/manage/article/fields', $account));
  }

  /**
   * @covers ::isBlocked
   *
   * Views UI paths should be blocked for editors in balanced profile.
   */
  public function testEditorBlockedFromViewsUi(): void {
    $configData = $this->balancedConfig();
    $this->config->method('get')->willReturnCallback(
      function (string $key = NULL) use ($configData) {
        return $key === NULL ? $configData : ($configData[$key] ?? NULL);
      }
    );

    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn('42');
    $account->method('isAnonymous')->willReturn(FALSE);
    $account->method('hasPermission')->willReturn(FALSE);
    $account->method('getRoles')->willReturn(['authenticated', 'editor']);

    $service = $this->buildService();

    self::assertTrue($service->isBlocked('/admin/structure/views', $account));
    self::assertTrue($service->isBlocked('/admin/structure/views/add', $account));
  }

  /**
   * @covers ::blockReason
   *
   * blockReason should reflect the actual block trigger.
   */
  public function testBlockReasonReturnsProfileString(): void {
    $configData = $this->balancedConfig();
    $this->config->method('get')->willReturnCallback(
      function (string $key = NULL) use ($configData) {
        return $key === NULL ? $configData : ($configData[$key] ?? NULL);
      }
    );

    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn('42');
    $account->method('getRoles')->willReturn(['editor']);

    $service = $this->buildService();

    $reason = $service->blockReason('/admin/structure/views', $account);
    self::assertStringContainsString('balanced', $reason);
    self::assertStringContainsString('Views UI', $reason);
  }

}
