<?php

declare(strict_types=1);

namespace Drupal\paranoia_reborn\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Render\Markup;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\paranoia_reborn\Service\ModuleHardener;
use Drupal\paranoia_reborn\Value\LockdownProfile;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Settings form for Paranoia Reborn.
 *
 * Allows administrators to select a lockdown profile, configure trusted/allowed
 * roles, manage per-path exceptions, and toggle individual protection features.
 */
final class ParanoiaRebornSettingsForm extends ConfigFormBase {

  use StringTranslationTrait;

  /**
   * The module hardener service.
   *
   * @var \Drupal\paranoia_reborn\Service\ModuleHardener
   */
  private ModuleHardener $moduleHardener;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = new static($container->get('config.factory'));
    $instance->moduleHardener = $container->get('paranoia_reborn.module_hardener');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['paranoia_reborn.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'paranoia_reborn_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config  = $this->config('paranoia_reborn.settings');
    $profile = $config->get('lockdown_profile') ?? 'balanced';

    // Warning banner if PHP filter is enabled.
    if ($this->moduleHardener->isPhpFilterEnabled()) {
      $form['php_filter_warning'] = [
        '#type'   => 'markup',
        '#markup' => Markup::create(
          '<div class="messages messages--error" role="alert">'
          . $this->t(
            '<strong>Critical security risk:</strong> The PHP filter module is currently ENABLED. '
            . 'This allows arbitrary PHP code execution from content fields. '
            . 'Save this form (with "Disable PHP filter" checked) to uninstall it immediately.'
          )
          . '</div>'
        ),
        '#weight' => -200,
      ];
    }

    // --- Lockdown Profile ---
    $form['profile_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Lockdown Profile'),
      '#open'  => TRUE,
    ];

    $form['profile_section']['lockdown_profile'] = [
      '#type'          => 'radios',
      '#title'         => $this->t('Active lockdown profile'),
      '#options'       => [
        'strict'   => $this->t('<strong>Strict</strong> — maximum protection: all features active, no admin-path exceptions except those explicitly listed below.'),
        'balanced' => $this->t('<strong>Balanced</strong> (recommended) — protects developer routes while allowing editors to access content management pages.'),
        'custom'   => $this->t('<strong>Custom</strong> — individually toggle each protection feature below.'),
      ],
      '#default_value' => $profile,
      '#required'      => TRUE,
    ];

    // --- Role Configuration ---
    $form['roles_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Role Configuration'),
      '#open'  => TRUE,
    ];

    $allRoles = $this->loadRoleOptions();

    $form['roles_section']['trusted_roles'] = [
      '#type'          => 'checkboxes',
      '#title'         => $this->t('Trusted (developer) roles'),
      '#description'   => $this->t(
        'Members of these roles bypass ALL Paranoia Reborn restrictions. '
        . 'Always include <em>administrator</em>. Treat this list like a developer allowlist.'
      ),
      '#options'       => $allRoles,
      '#default_value' => (array) ($config->get('trusted_roles') ?? ['administrator']),
    ];

    $form['roles_section']['admin_path_allowlist_roles'] = [
      '#type'          => 'checkboxes',
      '#title'         => $this->t('Admin-path allowlist roles (custom profile only)'),
      '#description'   => $this->t(
        'These roles may access <code>/admin/*</code> paths even when admin path restriction '
        . 'is active. Takes effect only in the <em>Custom</em> profile. '
        . 'In Strict/Balanced profiles, only trusted roles have access.'
      ),
      '#options'       => $allRoles,
      '#default_value' => (array) ($config->get('admin_path_allowlist_roles') ?? []),
      '#states'        => [
        'visible' => [':input[name="lockdown_profile"]' => ['value' => 'custom']],
      ],
    ];

    // --- Path Exceptions ---
    $form['exceptions_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Admin Path Exceptions'),
      '#open'  => FALSE,
    ];

    $currentExceptions = (array) ($config->get('admin_path_exceptions') ?? []);

    $form['exceptions_section']['admin_path_exceptions'] = [
      '#type'          => 'textarea',
      '#title'         => $this->t('Allowed admin paths (one per line)'),
      '#description'   => $this->t(
        'These <code>/admin/*</code> paths are always accessible to all authenticated users, '
        . 'regardless of the lockdown profile. Supports <code>/**</code> suffix wildcards. '
        . 'Example: <code>/admin/content</code> or <code>/admin/content/**</code>.'
      ),
      '#default_value' => implode("\n", $currentExceptions),
      '#rows'          => 6,
    ];

    // --- Custom Protection Toggles ---
    $form['custom_section'] = [
      '#type'   => 'details',
      '#title'  => $this->t('Custom Protection Toggles'),
      '#open'   => $profile === 'custom',
      '#states' => [
        'open' => [':input[name="lockdown_profile"]' => ['value' => 'custom']],
      ],
    ];

    $form['custom_section']['admin_path_restriction'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Restrict /admin/* paths'),
      '#description'   => $this->t(
        'Block access to all <code>/admin/*</code> paths for roles not in the trusted list '
        . '(or allowlist roles in custom mode). In Strict/Balanced profiles this is always on.'
      ),
      '#default_value' => (bool) ($config->get('admin_path_restriction') ?? TRUE),
      '#states'        => [
        'visible' => [':input[name="lockdown_profile"]' => ['value' => 'custom']],
      ],
    ];

    $form['custom_section']['disable_php_filter'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Disable PHP filter module'),
      '#description'   => $this->t(
        'Uninstall the <code>php</code> module (PHP filter) if it is currently enabled. '
        . 'This is a critical security measure — the PHP filter allows arbitrary code execution '
        . 'from text fields. Enabled in all profiles by default.'
      ),
      '#default_value' => (bool) ($config->get('disable_php_filter') ?? TRUE),
      '#states'        => [
        'visible' => [':input[name="lockdown_profile"]' => ['value' => 'custom']],
      ],
    ];

    $form['custom_section']['field_ui_restriction'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Restrict Field UI routes'),
      '#description'   => $this->t(
        'Hide <code>/admin/structure/types/manage/*/fields</code> and related Field UI '
        . 'routes from non-trusted roles. Prevents accidental schema changes by editors.'
      ),
      '#default_value' => (bool) ($config->get('field_ui_restriction') ?? TRUE),
      '#states'        => [
        'visible' => [':input[name="lockdown_profile"]' => ['value' => 'custom']],
      ],
    ];

    $form['custom_section']['views_ui_restriction'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Restrict Views UI routes'),
      '#description'   => $this->t(
        'Block access to <code>/admin/structure/views</code> for non-trusted roles. '
        . 'Prevents untrusted users from creating or editing views that could expose sensitive data.'
      ),
      '#default_value' => (bool) ($config->get('views_ui_restriction') ?? TRUE),
      '#states'        => [
        'visible' => [':input[name="lockdown_profile"]' => ['value' => 'custom']],
      ],
    ];

    // --- Audit Logging ---
    $form['audit_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Audit Logging'),
      '#open'  => TRUE,
    ];

    $form['audit_section']['audit_log_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable audit logging'),
      '#description'   => $this->t(
        'Write a watchdog (dblog) entry for every blocked access attempt. '
        . 'Includes the blocked path, user ID, roles, and IP address. '
        . '<a href=":url">View audit log</a>.',
        [':url' => Url::fromRoute('paranoia_reborn.audit_log')->toString()]
      ),
      '#default_value' => (bool) ($config->get('audit_log_enabled') ?? TRUE),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    $rawExceptions = trim((string) $form_state->getValue('admin_path_exceptions'));
    if ($rawExceptions !== '') {
      $lines = array_filter(array_map('trim', explode("\n", $rawExceptions)));
      foreach ($lines as $line) {
        if (!str_starts_with($line, '/')) {
          $form_state->setErrorByName(
            'admin_path_exceptions',
            $this->t('Each admin path exception must start with /. Invalid value: @val', ['@val' => $line])
          );
        }
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $profileId = (string) $form_state->getValue('lockdown_profile');

    // Derive effective boolean values: for strict/balanced we force all on.
    $isCustom = $profileId === 'custom';
    $forceOn  = !$isCustom;

    $trustedRoles = array_values(array_filter(
      (array) $form_state->getValue('trusted_roles')
    ));

    $allowlistRoles = array_values(array_filter(
      (array) $form_state->getValue('admin_path_allowlist_roles')
    ));

    // Parse multi-line textarea into a clean array.
    $rawExceptions = trim((string) $form_state->getValue('admin_path_exceptions'));
    $exceptions    = $rawExceptions !== ''
      ? array_values(array_filter(array_map('trim', explode("\n", $rawExceptions))))
      : [];

    $this->config('paranoia_reborn.settings')
      ->set('lockdown_profile', $profileId)
      ->set('trusted_roles', $trustedRoles)
      ->set('admin_path_allowlist_roles', $allowlistRoles)
      ->set('admin_path_exceptions', $exceptions)
      ->set('admin_path_restriction', $forceOn || (bool) $form_state->getValue('admin_path_restriction'))
      ->set('disable_php_filter', $forceOn || (bool) $form_state->getValue('disable_php_filter'))
      ->set('field_ui_restriction', $forceOn || (bool) $form_state->getValue('field_ui_restriction'))
      ->set('views_ui_restriction', $forceOn || (bool) $form_state->getValue('views_ui_restriction'))
      ->set('audit_log_enabled', (bool) $form_state->getValue('audit_log_enabled'))
      ->save();

    // Immediately apply PHP filter hardening if required.
    $this->moduleHardener->disablePhpFilterIfRequired();

    parent::submitForm($form, $form_state);
  }

  /**
   * Returns a list of all roles keyed by role ID for use in form checkboxes.
   *
   * @return array<string, \Drupal\Core\StringTranslation\TranslatableMarkup|string>
   */
  private function loadRoleOptions(): array {
    $roles   = \Drupal\user\Entity\Role::loadMultiple();
    $options = [];
    foreach ($roles as $rid => $role) {
      $options[$rid] = $role->label();
    }
    return $options;
  }

}
