<?php

declare(strict_types=1);

namespace Drupal\paranoia_reborn\Value;

/**
 * Immutable value object representing a Paranoia Reborn lockdown profile.
 *
 * Three built-in profiles are provided:
 *   - strict:   All protections enabled; no admin paths allowed for non-trusted
 *               roles; PHP filter disabled; Field UI and Views UI hidden.
 *   - balanced: Recommended defaults. Admin path restriction active but
 *               content-editor-safe exceptions pre-configured. PHP filter
 *               disabled. Field UI and Views UI hidden.
 *   - custom:   All toggles driven by the administrator's explicit settings.
 */
final readonly class LockdownProfile {

  /**
   * Constructs a LockdownProfile.
   *
   * @param string $id
   *   The profile machine name: 'strict', 'balanced', or 'custom'.
   * @param string $label
   *   Human-readable label.
   * @param bool $adminPathRestriction
   *   Block /admin/* for non-trusted roles.
   * @param bool $disablePhpFilter
   *   Disable the PHP filter module when enabled.
   * @param bool $fieldUiRestriction
   *   Hide Field UI routes from non-trusted roles.
   * @param bool $viewsUiRestriction
   *   Hide Views UI from non-trusted roles.
   * @param bool $auditLogEnabled
   *   Write blocked-access attempts to dblog.
   */
  public function __construct(
    public readonly string $id,
    public readonly string $label,
    public readonly bool $adminPathRestriction,
    public readonly bool $disablePhpFilter,
    public readonly bool $fieldUiRestriction,
    public readonly bool $viewsUiRestriction,
    public readonly bool $auditLogEnabled,
  ) {}

  /**
   * Returns the "strict" built-in profile (maximum protection).
   *
   * @return self
   */
  public static function strict(): self {
    return new self(
      id: 'strict',
      label: 'Strict (maximum protection)',
      adminPathRestriction: TRUE,
      disablePhpFilter: TRUE,
      fieldUiRestriction: TRUE,
      viewsUiRestriction: TRUE,
      auditLogEnabled: TRUE,
    );
  }

  /**
   * Returns the "balanced" built-in profile (recommended defaults).
   *
   * @return self
   */
  public static function balanced(): self {
    return new self(
      id: 'balanced',
      label: 'Balanced (recommended)',
      adminPathRestriction: TRUE,
      disablePhpFilter: TRUE,
      fieldUiRestriction: TRUE,
      viewsUiRestriction: TRUE,
      auditLogEnabled: TRUE,
    );
  }

  /**
   * Returns the "custom" profile stub (all toggles explicit via config).
   *
   * @param bool $adminPathRestriction
   *   Whether to restrict admin paths.
   * @param bool $disablePhpFilter
   *   Whether to disable the PHP filter module.
   * @param bool $fieldUiRestriction
   *   Whether to restrict Field UI routes.
   * @param bool $viewsUiRestriction
   *   Whether to restrict Views UI routes.
   * @param bool $auditLogEnabled
   *   Whether to enable audit logging.
   *
   * @return self
   */
  public static function custom(
    bool $adminPathRestriction,
    bool $disablePhpFilter,
    bool $fieldUiRestriction,
    bool $viewsUiRestriction,
    bool $auditLogEnabled,
  ): self {
    return new self(
      id: 'custom',
      label: 'Custom',
      adminPathRestriction: $adminPathRestriction,
      disablePhpFilter: $disablePhpFilter,
      fieldUiRestriction: $fieldUiRestriction,
      viewsUiRestriction: $viewsUiRestriction,
      auditLogEnabled: $auditLogEnabled,
    );
  }

  /**
   * Builds a LockdownProfile from a config array (as stored in config.factory).
   *
   * @param array<string, mixed> $config
   *   The raw config values from paranoia_reborn.settings.
   *
   * @return self
   *   The resolved profile, populated from the stored settings.
   */
  public static function fromConfig(array $config): self {
    $id = (string) ($config['lockdown_profile'] ?? 'balanced');

    return match ($id) {
      'strict'   => self::strict(),
      'balanced' => self::balanced(),
      default    => self::custom(
        adminPathRestriction: (bool) ($config['admin_path_restriction'] ?? TRUE),
        disablePhpFilter:     (bool) ($config['disable_php_filter'] ?? TRUE),
        fieldUiRestriction:   (bool) ($config['field_ui_restriction'] ?? TRUE),
        viewsUiRestriction:   (bool) ($config['views_ui_restriction'] ?? TRUE),
        auditLogEnabled:      (bool) ($config['audit_log_enabled'] ?? TRUE),
      ),
    };
  }

  /**
   * Returns all available profile machine names.
   *
   * @return list<string>
   */
  public static function availableIds(): array {
    return ['strict', 'balanced', 'custom'];
  }

  /**
   * Returns human-readable labels keyed by profile ID.
   *
   * @return array<string, string>
   */
  public static function labels(): array {
    return [
      'strict'   => 'Strict (maximum protection)',
      'balanced' => 'Balanced (recommended)',
      'custom'   => 'Custom',
    ];
  }

}
