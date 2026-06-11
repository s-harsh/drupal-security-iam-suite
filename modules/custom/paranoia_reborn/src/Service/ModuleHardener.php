<?php

declare(strict_types=1);

namespace Drupal\paranoia_reborn\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Extension\ModuleInstallerInterface;
use Drupal\paranoia_reborn\Value\LockdownProfile;
use Psr\Log\LoggerInterface;

/**
 * Performs module-level hardening actions on behalf of Paranoia Reborn.
 *
 * Currently responsible for:
 *   - Detecting and optionally disabling the PHP filter module (CVE vector).
 *
 * The service is intentionally narrow: each hardening action is a discrete
 * method so callers (hooks, Drush commands) can invoke them independently.
 */
final class ModuleHardener {

  /**
   * The machine name of the PHP filter module.
   */
  private const PHP_FILTER_MODULE = 'php';

  /**
   * Constructs a ModuleHardener.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   Used to check whether modules are currently installed.
   * @param \Drupal\Core\Extension\ModuleInstallerInterface $moduleInstaller
   *   Used to uninstall modules programmatically.
   * @param \Psr\Log\LoggerInterface $logger
   *   The paranoia_reborn logger channel.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly ModuleInstallerInterface $moduleInstaller,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Returns TRUE if the PHP filter module is currently installed.
   *
   * @return bool
   */
  public function isPhpFilterEnabled(): bool {
    return $this->moduleHandler->moduleExists(self::PHP_FILTER_MODULE);
  }

  /**
   * Disables the PHP filter module if it is installed and the profile requires it.
   *
   * Safe to call repeatedly: is a no-op when the module is already disabled.
   *
   * @return bool
   *   TRUE if the module was uninstalled during this call, FALSE otherwise.
   *
   * @throws \Drupal\Core\Extension\Exception\ObsoleteExtensionException
   *   If the module cannot be uninstalled due to dependency constraints.
   */
  public function disablePhpFilterIfRequired(): bool {
    $config  = $this->configFactory->get('paranoia_reborn.settings');
    $profile = LockdownProfile::fromConfig($config->get() ?? []);

    if (!$profile->disablePhpFilter) {
      return FALSE;
    }

    if (!$this->isPhpFilterEnabled()) {
      return FALSE;
    }

    try {
      $this->moduleInstaller->uninstall([self::PHP_FILTER_MODULE]);
      $this->logger->warning(
        'Paranoia Reborn: the PHP filter module (@module) was uninstalled because it poses a critical remote-code-execution risk. Profile: @profile.',
        [
          '@module'  => self::PHP_FILTER_MODULE,
          '@profile' => $profile->id,
        ]
      );
      return TRUE;
    }
    catch (\Exception $e) {
      $this->logger->error(
        'Paranoia Reborn: attempted to uninstall the PHP filter module but failed: @message',
        ['@message' => $e->getMessage()]
      );
      return FALSE;
    }
  }

  /**
   * Returns a structured summary of the current hardening status.
   *
   * Used by the status report integration (hook_requirements).
   *
   * @return array<string, mixed>
   *   Associative array with keys:
   *     - profile (string): active profile ID.
   *     - php_filter_installed (bool): whether the PHP filter module is present.
   *     - admin_path_restriction (bool): active state from profile.
   *     - field_ui_restriction (bool): active state from profile.
   *     - views_ui_restriction (bool): active state from profile.
   *     - audit_log_enabled (bool): active state from profile.
   */
  public function hardeningStatus(): array {
    $config  = $this->configFactory->get('paranoia_reborn.settings');
    $profile = LockdownProfile::fromConfig($config->get() ?? []);

    return [
      'profile'               => $profile->id,
      'php_filter_installed'  => $this->isPhpFilterEnabled(),
      'admin_path_restriction' => $profile->adminPathRestriction,
      'field_ui_restriction'  => $profile->fieldUiRestriction,
      'views_ui_restriction'  => $profile->viewsUiRestriction,
      'audit_log_enabled'     => $profile->auditLogEnabled,
    ];
  }

}
