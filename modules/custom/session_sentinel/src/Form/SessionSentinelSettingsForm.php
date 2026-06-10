<?php

declare(strict_types=1);

namespace Drupal\session_sentinel\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Administration settings form for Session Sentinel.
 *
 * Provides configuration for idle timeout (global and per-role),
 * concurrent session limiting, and device fingerprint binding.
 */
final class SessionSentinelSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static($container->get('config.factory'));
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['session_sentinel.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'session_sentinel_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('session_sentinel.settings');

    // ---- Idle Timeout --------------------------------------------------------
    $form['idle_timeout_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Idle Session Timeout'),
      '#open'  => TRUE,
    ];

    $form['idle_timeout_section']['idle_timeout'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Global idle timeout (seconds)'),
      '#description'   => $this->t('Sessions idle for longer than this value will be expired. Set to <code>0</code> to disable idle timeout globally. Default: 1800 (30 minutes).'),
      '#default_value' => $config->get('idle_timeout') ?? 1800,
      '#min'           => 0,
      '#max'           => 86400,
      '#required'      => TRUE,
    ];

    $form['idle_timeout_section']['warning_lead_time'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Warning lead time (seconds)'),
      '#description'   => $this->t('Seconds before session expiry at which the JavaScript countdown warning banner appears. Must be less than the idle timeout. Default: 300 (5 minutes).'),
      '#default_value' => $config->get('warning_lead_time') ?? 300,
      '#min'           => 30,
      '#max'           => 3600,
      '#required'      => TRUE,
    ];

    // Per-role timeouts.
    $form['idle_timeout_section']['role_timeouts'] = [
      '#type'  => 'details',
      '#title' => $this->t('Per-role idle timeout overrides'),
      '#open'  => FALSE,
    ];

    $form['idle_timeout_section']['role_timeouts']['role_timeouts_description'] = [
      '#markup' => '<p>' . $this->t('Set a per-role idle timeout in seconds. <code>0</code> means inherit the global value. The tightest (lowest non-zero) role timeout applies when a user has multiple roles.') . '</p>',
    ];

    $roles = \Drupal\user\Entity\Role::loadMultiple();
    $roleTimeouts = (array) ($config->get('role_timeouts') ?? []);

    foreach ($roles as $roleId => $role) {
      if ($roleId === 'anonymous') {
        continue;
      }
      $form['idle_timeout_section']['role_timeouts']['role_timeout_' . $roleId] = [
        '#type'          => 'number',
        '#title'         => $this->t('Timeout for role "@role" (seconds, 0 = global)', ['@role' => $role->label()]),
        '#default_value' => $roleTimeouts[$roleId] ?? 0,
        '#min'           => 0,
        '#max'           => 86400,
      ];
    }

    // ---- Concurrent Session Limit --------------------------------------------
    $form['concurrent_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Concurrent Session Limiting'),
      '#open'  => TRUE,
    ];

    $form['concurrent_section']['max_concurrent_sessions'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Maximum concurrent sessions per user'),
      '#description'   => $this->t('When a new login creates a session that exceeds this limit, the oldest session is killed automatically. Set to <code>0</code> for unlimited. Default: 3.'),
      '#default_value' => $config->get('max_concurrent_sessions') ?? 3,
      '#min'           => 0,
      '#max'           => 100,
      '#required'      => TRUE,
    ];

    $form['concurrent_section']['exempt_admins_from_limit'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Exempt administrators from the concurrent session limit'),
      '#description'   => $this->t('When enabled, uid=1 and users with the <em>Administer users</em> permission are not subject to the concurrent session limit.'),
      '#default_value' => $config->get('exempt_admins_from_limit') ?? TRUE,
    ];

    // ---- Device Fingerprint Binding ------------------------------------------
    $form['device_binding_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Device Fingerprint Binding'),
      '#open'  => TRUE,
    ];

    $form['device_binding_section']['enable_device_binding'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable device fingerprint anomaly detection'),
      '#description'   => $this->t('Generates a SHA-256 fingerprint from the User-Agent and /24 IP subnet on login. Subsequent requests with a different fingerprint are considered anomalous.'),
      '#default_value' => $config->get('enable_device_binding') ?? TRUE,
    ];

    $form['device_binding_section']['kill_on_device_change'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Kill session on device fingerprint change'),
      '#description'   => $this->t('When enabled, an anomalous fingerprint change immediately terminates the session. When disabled (default), the session is only flagged in the dashboard and a warning is logged.'),
      '#default_value' => $config->get('kill_on_device_change') ?? FALSE,
      '#states'        => [
        'visible' => [
          ':input[name="enable_device_binding"]' => ['checked' => TRUE],
        ],
      ],
    ];

    // ---- Maintenance ---------------------------------------------------------
    $form['maintenance_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('Maintenance'),
      '#open'  => FALSE,
    ];

    $form['maintenance_section']['prune_age'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Stale record prune age (seconds)'),
      '#description'   => $this->t('Session sentinel records with no activity for longer than this value are deleted during cron and by <code>drush session-sentinel:prune</code>. Default: 604800 (7 days).'),
      '#default_value' => $config->get('prune_age') ?? 604800,
      '#min'           => 3600,
      '#max'           => 2592000,
      '#required'      => TRUE,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    $idleTimeout = (int) $form_state->getValue('idle_timeout');
    if ($idleTimeout < 0) {
      $form_state->setErrorByName('idle_timeout', $this->t('Idle timeout cannot be negative.'));
    }

    $warningLeadTime = (int) $form_state->getValue('warning_lead_time');
    if ($warningLeadTime < 30) {
      $form_state->setErrorByName('warning_lead_time', $this->t('Warning lead time must be at least 30 seconds.'));
    }

    if ($idleTimeout > 0 && $warningLeadTime >= $idleTimeout) {
      $form_state->setErrorByName(
        'warning_lead_time',
        $this->t('Warning lead time must be less than the idle timeout.')
      );
    }

    $maxSessions = (int) $form_state->getValue('max_concurrent_sessions');
    if ($maxSessions < 0) {
      $form_state->setErrorByName('max_concurrent_sessions', $this->t('Maximum concurrent sessions cannot be negative.'));
    }

    $pruneAge = (int) $form_state->getValue('prune_age');
    if ($pruneAge < 3600) {
      $form_state->setErrorByName('prune_age', $this->t('Prune age must be at least 3600 seconds (1 hour).'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $config = $this->config('session_sentinel.settings');

    // Collect per-role timeouts.
    $roles = \Drupal\user\Entity\Role::loadMultiple();
    $roleTimeouts = [];
    foreach ($roles as $roleId => $role) {
      if ($roleId === 'anonymous') {
        continue;
      }
      $value = (int) ($form_state->getValue('role_timeout_' . $roleId) ?? 0);
      if ($value > 0) {
        $roleTimeouts[$roleId] = $value;
      }
    }

    $config
      ->set('idle_timeout', (int) $form_state->getValue('idle_timeout'))
      ->set('warning_lead_time', (int) $form_state->getValue('warning_lead_time'))
      ->set('role_timeouts', $roleTimeouts)
      ->set('max_concurrent_sessions', (int) $form_state->getValue('max_concurrent_sessions'))
      ->set('exempt_admins_from_limit', (bool) $form_state->getValue('exempt_admins_from_limit'))
      ->set('enable_device_binding', (bool) $form_state->getValue('enable_device_binding'))
      ->set('kill_on_device_change', (bool) $form_state->getValue('kill_on_device_change'))
      ->set('prune_age', (int) $form_state->getValue('prune_age'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
