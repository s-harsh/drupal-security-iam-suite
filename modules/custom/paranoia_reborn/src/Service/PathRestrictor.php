<?php

declare(strict_types=1);

namespace Drupal\paranoia_reborn\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\paranoia_reborn\Value\LockdownProfile;
use Psr\Log\LoggerInterface;

/**
 * Determines whether a given request path should be blocked for the current user.
 *
 * Path restriction logic is isolated here so it can be unit-tested without
 * bootstrapping a full kernel. The service is stateless with respect to the
 * request — it receives path and account as arguments rather than reading them
 * from the request stack, which makes it easy to mock in tests.
 */
final class PathRestrictor {

  /**
   * Constructs a PathRestrictor.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Session\AccountInterface $currentUser
   *   The currently authenticated account, used for role checks.
   * @param \Psr\Log\LoggerInterface $logger
   *   The paranoia_reborn logger channel.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly AccountInterface $currentUser,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Returns TRUE if the given path should be blocked for the given account.
   *
   * @param string $path
   *   The decoded request path (e.g. /admin/structure/types).
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account whose access is being checked.
   *
   * @return bool
   *   TRUE if the path must be blocked; FALSE to allow normal access checking.
   */
  public function isBlocked(string $path, AccountInterface $account): bool {
    // Anonymous users are always blocked from /admin/*; Drupal's own
    // permission system handles this separately, but we enforce it here too
    // so audit log entries are consistent.
    if ($account->isAnonymous()) {
      return $this->isAdminPath($path) || $this->isFieldUiPath($path) || $this->isViewsUiPath($path);
    }

    // UID 1 and accounts with the bypass permission are never blocked.
    if ($this->isTrusted($account)) {
      return FALSE;
    }

    $config  = $this->configFactory->get('paranoia_reborn.settings');
    $profile = LockdownProfile::fromConfig($config->get() ?? []);

    // Admin path restriction.
    if ($profile->adminPathRestriction && $this->isAdminPath($path)) {
      if ($this->isAdminPathException($path, $config->get('admin_path_exceptions') ?? [])) {
        return FALSE;
      }
      // In custom profile, check explicit role allowlist.
      if ($profile->id === 'custom') {
        $allowlistRoles = (array) ($config->get('admin_path_allowlist_roles') ?? []);
        foreach ($account->getRoles() as $role) {
          if (in_array($role, $allowlistRoles, TRUE)) {
            return FALSE;
          }
        }
      }
      return TRUE;
    }

    // Field UI restriction.
    if ($profile->fieldUiRestriction && $this->isFieldUiPath($path)) {
      return TRUE;
    }

    // Views UI restriction.
    if ($profile->viewsUiRestriction && $this->isViewsUiPath($path)) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * Returns the human-readable reason a path is blocked (for audit logging).
   *
   * @param string $path
   *   The request path.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account that was blocked.
   *
   * @return string
   *   A short description of the block reason.
   */
  public function blockReason(string $path, AccountInterface $account): string {
    $config  = $this->configFactory->get('paranoia_reborn.settings');
    $profile = LockdownProfile::fromConfig($config->get() ?? []);

    if ($this->isFieldUiPath($path)) {
      return sprintf('Field UI route blocked (profile: %s)', $profile->id);
    }
    if ($this->isViewsUiPath($path)) {
      return sprintf('Views UI route blocked (profile: %s)', $profile->id);
    }
    return sprintf('Admin path blocked (profile: %s)', $profile->id);
  }

  /**
   * Resolves the active LockdownProfile from current configuration.
   *
   * @return \Drupal\paranoia_reborn\Value\LockdownProfile
   *   The active profile.
   */
  public function activeProfile(): LockdownProfile {
    $config = $this->configFactory->get('paranoia_reborn.settings');
    return LockdownProfile::fromConfig($config->get() ?? []);
  }

  /**
   * Returns TRUE when the account is a trusted developer.
   *
   * An account is trusted when any of the following is true:
   *   - It is UID 1 (the Drupal super-admin).
   *   - It holds the 'bypass paranoia reborn restrictions' permission.
   *   - Any of its roles is listed in the configured trusted_roles.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account to check.
   *
   * @return bool
   */
  public function isTrusted(AccountInterface $account): bool {
    if ((int) $account->id() === 1) {
      return TRUE;
    }

    if ($account->hasPermission('bypass paranoia reborn restrictions')) {
      return TRUE;
    }

    $config       = $this->configFactory->get('paranoia_reborn.settings');
    $trustedRoles = (array) ($config->get('trusted_roles') ?? []);
    foreach ($account->getRoles() as $role) {
      if (in_array($role, $trustedRoles, TRUE)) {
        return TRUE;
      }
    }

    return FALSE;
  }

  /**
   * Returns TRUE if $path starts with /admin/.
   *
   * @param string $path
   *   The decoded request path.
   *
   * @return bool
   */
  public function isAdminPath(string $path): bool {
    return str_starts_with($path, '/admin/') || $path === '/admin';
  }

  /**
   * Returns TRUE if $path is a Field UI management route.
   *
   * Field UI routes follow the pattern:
   *   /admin/structure/types/manage/{bundle}/fields
   *   /admin/structure/types/manage/{bundle}/form-display
   *   /admin/structure/types/manage/{bundle}/display
   *   (and the taxonomy / block / paragraph equivalents)
   *
   * @param string $path
   *   The decoded request path.
   *
   * @return bool
   */
  public function isFieldUiPath(string $path): bool {
    // Catch all Field UI sub-paths across all entity types.
    $fieldUiPatterns = [
      '#^/admin/structure/types/manage/[^/]+/fields(/.*)?$#',
      '#^/admin/structure/types/manage/[^/]+/form-display(/.*)?$#',
      '#^/admin/structure/types/manage/[^/]+/display(/.*)?$#',
      '#^/admin/structure/taxonomy/manage/[^/]+/fields(/.*)?$#',
      '#^/admin/structure/taxonomy/manage/[^/]+/form-display(/.*)?$#',
      '#^/admin/structure/taxonomy/manage/[^/]+/display(/.*)?$#',
      '#^/admin/structure/block/block-content/manage/[^/]+/fields(/.*)?$#',
      '#^/admin/structure/paragraphs_type/[^/]+/fields(/.*)?$#',
    ];

    foreach ($fieldUiPatterns as $pattern) {
      if (preg_match($pattern, $path) === 1) {
        return TRUE;
      }
    }

    return FALSE;
  }

  /**
   * Returns TRUE if $path is a Views UI route.
   *
   * @param string $path
   *   The decoded request path.
   *
   * @return bool
   */
  public function isViewsUiPath(string $path): bool {
    return str_starts_with($path, '/admin/structure/views')
      || str_starts_with($path, '/admin/reports/views');
  }

  /**
   * Returns TRUE if the path matches one of the configured admin exceptions.
   *
   * Exceptions may use exact paths or trailing /** wildcards.
   *
   * @param string $path
   *   The request path.
   * @param mixed $exceptions
   *   The raw config value (list of path strings).
   *
   * @return bool
   */
  private function isAdminPathException(string $path, mixed $exceptions): bool {
    if (!is_array($exceptions)) {
      return FALSE;
    }

    foreach ($exceptions as $exception) {
      $exception = (string) $exception;
      if (str_ends_with($exception, '/**')) {
        $prefix = rtrim(substr($exception, 0, -3), '/');
        if ($path === $prefix || str_starts_with($path, $prefix . '/')) {
          return TRUE;
        }
      }
      elseif ($exception === $path) {
        return TRUE;
      }
    }

    return FALSE;
  }

}
