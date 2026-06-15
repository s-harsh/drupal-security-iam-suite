<?php

declare(strict_types=1);

namespace Drupal\Tests\paranoia_reborn\Unit\Service;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Extension\ModuleInstallerInterface;
use Drupal\paranoia_reborn\Service\ModuleHardener;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

/**
 * Unit tests for ModuleHardener.
 *
 * @coversDefaultClass \Drupal\paranoia_reborn\Service\ModuleHardener
 * @group paranoia_reborn
 */
final class ModuleHardenerTest extends TestCase {

  /**
   * @var \Drupal\Core\Config\Config&\PHPUnit\Framework\MockObject\MockObject
   */
  private Config&MockObject $config;

  /**
   * @var \Drupal\Core\Config\ConfigFactoryInterface&\PHPUnit\Framework\MockObject\MockObject
   */
  private ConfigFactoryInterface&MockObject $configFactory;

  /**
   * @var \Drupal\Core\Extension\ModuleHandlerInterface&\PHPUnit\Framework\MockObject\MockObject
   */
  private ModuleHandlerInterface&MockObject $moduleHandler;

  /**
   * @var \Drupal\Core\Extension\ModuleInstallerInterface&\PHPUnit\Framework\MockObject\MockObject
   */
  private ModuleInstallerInterface&MockObject $moduleInstaller;

  /**
   * @var \Psr\Log\LoggerInterface&\PHPUnit\Framework\MockObject\MockObject
   */
  private LoggerInterface&MockObject $logger;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->config          = $this->createMock(Config::class);
    $this->configFactory   = $this->createMock(ConfigFactoryInterface::class);
    $this->moduleHandler   = $this->createMock(ModuleHandlerInterface::class);
    $this->moduleInstaller = $this->createMock(ModuleInstallerInterface::class);
    $this->logger          = $this->createMock(LoggerInterface::class);

    $this->configFactory
      ->method('get')
      ->with('paranoia_reborn.settings')
      ->willReturn($this->config);
  }

  /**
   * Builds a ModuleHardener with the current mocks.
   */
  private function buildService(): ModuleHardener {
    return new ModuleHardener(
      $this->configFactory,
      $this->moduleHandler,
      $this->moduleInstaller,
      $this->logger,
    );
  }

  /**
   * @covers ::isPhpFilterEnabled
   */
  public function testIsPhpFilterEnabledReturnsTrueWhenInstalled(): void {
    $this->moduleHandler
      ->method('moduleExists')
      ->with('php')
      ->willReturn(TRUE);

    $service = $this->buildService();
    self::assertTrue($service->isPhpFilterEnabled());
  }

  /**
   * @covers ::isPhpFilterEnabled
   */
  public function testIsPhpFilterEnabledReturnsFalseWhenNotInstalled(): void {
    $this->moduleHandler
      ->method('moduleExists')
      ->with('php')
      ->willReturn(FALSE);

    $service = $this->buildService();
    self::assertFalse($service->isPhpFilterEnabled());
  }

  /**
   * @covers ::disablePhpFilterIfRequired
   *
   * When PHP filter is not installed, uninstall should never be called.
   */
  public function testDisablePhpFilterSkippedWhenNotInstalled(): void {
    $this->config->method('get')->willReturn([
      'lockdown_profile' => 'balanced',
      'disable_php_filter' => TRUE,
    ]);

    $this->moduleHandler
      ->method('moduleExists')
      ->with('php')
      ->willReturn(FALSE);

    $this->moduleInstaller
      ->expects(self::never())
      ->method('uninstall');

    $service = $this->buildService();
    $result  = $service->disablePhpFilterIfRequired();

    self::assertFalse($result);
  }

  /**
   * @covers ::disablePhpFilterIfRequired
   *
   * When profile says disable and PHP filter is installed, uninstall is called.
   */
  public function testDisablePhpFilterUninstallsWhenRequired(): void {
    $this->config->method('get')->willReturn([
      'lockdown_profile' => 'strict',
      'disable_php_filter' => TRUE,
    ]);

    $this->moduleHandler
      ->method('moduleExists')
      ->with('php')
      ->willReturn(TRUE);

    $this->moduleInstaller
      ->expects(self::once())
      ->method('uninstall')
      ->with(['php']);

    $this->logger
      ->expects(self::once())
      ->method('warning');

    $service = $this->buildService();
    $result  = $service->disablePhpFilterIfRequired();

    self::assertTrue($result);
  }

  /**
   * @covers ::disablePhpFilterIfRequired
   *
   * In custom profile with disable_php_filter=FALSE, no uninstall occurs.
   */
  public function testDisablePhpFilterSkippedWhenProfileDisablesIt(): void {
    $this->config->method('get')->willReturn([
      'lockdown_profile'   => 'custom',
      'disable_php_filter' => FALSE,
    ]);

    $this->moduleHandler
      ->method('moduleExists')
      ->with('php')
      ->willReturn(TRUE);

    $this->moduleInstaller
      ->expects(self::never())
      ->method('uninstall');

    $service = $this->buildService();
    $result  = $service->disablePhpFilterIfRequired();

    self::assertFalse($result);
  }

  /**
   * @covers ::disablePhpFilterIfRequired
   *
   * When uninstall throws, the method returns FALSE and logs an error.
   */
  public function testDisablePhpFilterHandlesUninstallException(): void {
    $this->config->method('get')->willReturn([
      'lockdown_profile' => 'balanced',
      'disable_php_filter' => TRUE,
    ]);

    $this->moduleHandler
      ->method('moduleExists')
      ->with('php')
      ->willReturn(TRUE);

    $this->moduleInstaller
      ->method('uninstall')
      ->willThrowException(new \RuntimeException('Module has dependents.'));

    $this->logger
      ->expects(self::once())
      ->method('error');

    $service = $this->buildService();
    $result  = $service->disablePhpFilterIfRequired();

    self::assertFalse($result);
  }

  /**
   * @covers ::hardeningStatus
   */
  public function testHardeningStatusReturnsExpectedKeys(): void {
    $this->config->method('get')->willReturn([
      'lockdown_profile'      => 'balanced',
      'disable_php_filter'    => TRUE,
      'admin_path_restriction' => TRUE,
      'field_ui_restriction'  => TRUE,
      'views_ui_restriction'  => TRUE,
      'audit_log_enabled'     => TRUE,
    ]);

    $this->moduleHandler
      ->method('moduleExists')
      ->with('php')
      ->willReturn(FALSE);

    $service = $this->buildService();
    $status  = $service->hardeningStatus();

    self::assertArrayHasKey('profile', $status);
    self::assertArrayHasKey('php_filter_installed', $status);
    self::assertArrayHasKey('admin_path_restriction', $status);
    self::assertArrayHasKey('field_ui_restriction', $status);
    self::assertArrayHasKey('views_ui_restriction', $status);
    self::assertArrayHasKey('audit_log_enabled', $status);
    self::assertSame('balanced', $status['profile']);
    self::assertFalse($status['php_filter_installed']);
    self::assertTrue($status['admin_path_restriction']);
  }

}
