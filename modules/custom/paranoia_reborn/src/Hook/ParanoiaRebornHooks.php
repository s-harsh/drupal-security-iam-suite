<?php

declare(strict_types=1);

namespace Drupal\paranoia_reborn\Hook;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\paranoia_reborn\Service\ModuleHardener;
use Drupal\paranoia_reborn\Value\LockdownProfile;

/**
 * OOP hook implementations for the Paranoia Reborn module.
 *
 * Hooks are registered via the #[Hook] attribute. This class is tagged as a
 * drupal.hook service so Drupal 11's hook discovery picks it up automatically.
 */
final class ParanoiaRebornHooks {

  use StringTranslationTrait;

  /**
   * Constructs a ParanoiaRebornHooks instance.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\paranoia_reborn\Service\ModuleHardener $moduleHardener
   *   The module hardener service.
   * @param \Drupal\Core\Session\AccountInterface $currentUser
   *   The current user.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler.
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection (for audit log counts in requirements).
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly ModuleHardener $moduleHardener,
    private readonly AccountInterface $currentUser,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly Connection $database,
  ) {}

  /**
   * Implements hook_requirements().
   *
   * Surfaces Paranoia Reborn hardening status in the Drupal status report.
   */
  #[Hook('requirements')]
  public function requirements(string $phase): array {
    if ($phase !== 'runtime') {
      return [];
    }

    $requirements = [];
    $status = $this->moduleHardener->hardeningStatus();
    $config = $this->configFactory->get('paranoia_reborn.settings');

    // --- Active lockdown profile ---
    $profileLabels = LockdownProfile::labels();
    $profileLabel  = $profileLabels[$status['profile']] ?? $status['profile'];

    $requirements['paranoia_reborn_profile'] = [
      'title'    => $this->t('Paranoia Reborn — Lockdown Profile'),
      'value'    => $this->t('@profile active', ['@profile' => $profileLabel]),
      'severity' => REQUIREMENT_INFO,
      'description' => $this->t(
        'Manage settings at <a href=":url">Paranoia Reborn Settings</a>.',
        [':url' => Url::fromRoute('paranoia_reborn.settings')->toString()]
      ),
    ];

    // --- PHP filter module ---
    if ($status['php_filter_installed']) {
      $requirements['paranoia_reborn_php_filter'] = [
        'title'       => $this->t('Paranoia Reborn — PHP Filter'),
        'value'       => $this->t('PHP filter module is ENABLED — critical RCE risk.'),
        'severity'    => REQUIREMENT_ERROR,
        'description' => $this->t(
          'The <code>php</code> module allows PHP code to be executed from text fields. '
          . 'This is a critical attack surface. Paranoia Reborn is configured to disable it '
          . 'but it appears to still be active. '
          . '<a href=":url">Check settings</a>.',
          [':url' => Url::fromRoute('paranoia_reborn.settings')->toString()]
        ),
      ];
    }
    else {
      $requirements['paranoia_reborn_php_filter'] = [
        'title'    => $this->t('Paranoia Reborn — PHP Filter'),
        'value'    => $this->t('PHP filter module is not installed (secure).'),
        'severity' => REQUIREMENT_OK,
      ];
    }

    // --- Admin path restriction ---
    $requirements['paranoia_reborn_admin_paths'] = [
      'title'    => $this->t('Paranoia Reborn — Admin Path Restriction'),
      'value'    => $status['admin_path_restriction']
        ? $this->t('Admin path restriction: ACTIVE')
        : $this->t('Admin path restriction: disabled'),
      'severity' => $status['admin_path_restriction'] ? REQUIREMENT_OK : REQUIREMENT_WARNING,
    ];

    // --- Field UI restriction ---
    $requirements['paranoia_reborn_field_ui'] = [
      'title'    => $this->t('Paranoia Reborn — Field UI Restriction'),
      'value'    => $status['field_ui_restriction']
        ? $this->t('Field UI restriction: ACTIVE')
        : $this->t('Field UI restriction: disabled'),
      'severity' => $status['field_ui_restriction'] ? REQUIREMENT_OK : REQUIREMENT_WARNING,
    ];

    // --- Views UI restriction ---
    $requirements['paranoia_reborn_views_ui'] = [
      'title'    => $this->t('Paranoia Reborn — Views UI Restriction'),
      'value'    => $status['views_ui_restriction']
        ? $this->t('Views UI restriction: ACTIVE')
        : $this->t('Views UI restriction: disabled'),
      'severity' => $status['views_ui_restriction'] ? REQUIREMENT_OK : REQUIREMENT_WARNING,
    ];

    // --- Audit log: recent block count ---
    $blockedCount = 0;
    try {
      $blockedCount = (int) $this->database->select('watchdog', 'w')
        ->condition('w.type', 'paranoia_reborn')
        ->countQuery()
        ->execute()
        ->fetchField();
    }
    catch (\Exception) {
      // watchdog table may not exist in minimal installs or during testing.
    }

    $requirements['paranoia_reborn_audit'] = [
      'title'    => $this->t('Paranoia Reborn — Audit Log'),
      'value'    => $status['audit_log_enabled']
        ? $this->t('Audit logging enabled. @count blocked attempts recorded.', ['@count' => $blockedCount])
        : $this->t('Audit logging disabled.'),
      'severity' => REQUIREMENT_INFO,
      'description' => $this->t(
        '<a href=":url">View audit log</a>.',
        [':url' => Url::fromRoute('paranoia_reborn.audit_log')->toString()]
      ),
    ];

    return $requirements;
  }

  /**
   * Implements hook_help().
   */
  #[Hook('help')]
  public function help(string $route_name, RouteMatchInterface $route_match): string|array {
    if ($route_name !== 'help.page.paranoia_reborn') {
      return '';
    }

    return [
      '#type'   => 'markup',
      '#markup' => $this->t(
        '<p><strong>Paranoia Reborn</strong> is a modern replacement for the abandoned Paranoia module. '
        . 'It protects Drupal 11 sites by:</p>'
        . '<ul>'
        . '<li>Blocking non-privileged roles from accessing <code>/admin/*</code> paths (configurable exceptions).</li>'
        . '<li>Disabling the PHP filter module — a critical remote code execution vector.</li>'
        . '<li>Hiding Field UI routes (<code>/admin/structure/types/manage/*/fields</code>) from non-developers.</li>'
        . '<li>Restricting the Views UI to developer roles.</li>'
        . '<li>Three lockdown profiles: <em>Strict</em>, <em>Balanced</em> (recommended), and <em>Custom</em>.</li>'
        . '<li>An audit log of every blocked attempt, written to Drupal\'s watchdog (dblog).</li>'
        . '</ul>'
        . '<p><a href=":settings_url">Configure Paranoia Reborn</a> | <a href=":audit_url">View Audit Log</a></p>',
        [
          ':settings_url' => Url::fromRoute('paranoia_reborn.settings')->toString(),
          ':audit_url'    => Url::fromRoute('paranoia_reborn.audit_log')->toString(),
        ]
      ),
    ];
  }

  /**
   * Implements hook_modules_installed().
   *
   * Immediately disables the PHP filter module if it is installed while
   * Paranoia Reborn is active and the profile requires it.
   *
   * @param string[] $modules
   *   Array of module machine names that were just installed.
   */
  #[Hook('modules_installed')]
  public function modulesInstalled(array $modules): void {
    if (in_array('php', $modules, TRUE)) {
      $this->moduleHardener->disablePhpFilterIfRequired();
    }
  }

  /**
   * Implements hook_menu_links_discovered_alter().
   *
   * Hides the Field UI and Views UI menu links from non-trusted users so they
   * do not appear in the admin toolbar even when path restriction blocks the
   * actual route.
   *
   * @param array<string, mixed> $links
   *   The discovered menu link definitions, keyed by plugin ID.
   */
  #[Hook('menu_links_discovered_alter')]
  public function menuLinksDiscoveredAlter(array &$links): void {
    if ($this->currentUser->isAnonymous()) {
      return;
    }

    $config  = $this->configFactory->get('paranoia_reborn.settings');
    $profile = LockdownProfile::fromConfig($config->get() ?? []);

    // Check if user has bypass permission before hiding links.
    if ($this->currentUser->hasPermission('bypass paranoia reborn restrictions')
      || $this->currentUser->hasPermission('administer paranoia reborn')
      || (int) $this->currentUser->id() === 1) {
      return;
    }

    // Hide Field UI links.
    if ($profile->fieldUiRestriction) {
      foreach (array_keys($links) as $linkId) {
        if (str_contains((string) $linkId, 'field_ui.fields')
          || str_contains((string) $linkId, 'field_ui.form_display')
          || str_contains((string) $linkId, 'field_ui.display')) {
          unset($links[$linkId]);
        }
      }
    }

    // Hide Views UI links.
    if ($profile->viewsUiRestriction && $this->moduleHandler->moduleExists('views_ui')) {
      $viewsUiLinks = [
        'views_ui.list',
        'views_ui.add',
      ];
      foreach ($viewsUiLinks as $linkId) {
        unset($links[$linkId]);
      }
    }
  }

}
