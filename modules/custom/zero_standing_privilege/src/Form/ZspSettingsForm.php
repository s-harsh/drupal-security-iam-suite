<?php

declare(strict_types=1);

namespace Drupal\zero_standing_privilege\Form;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Administration settings form for Zero Standing Privilege.
 */
final class ZspSettingsForm extends ConfigFormBase {

  private EntityTypeManagerInterface $entityTypeManager;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = new static($container->get('config.factory'));
    $instance->entityTypeManager = $container->get('entity_type.manager');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['zero_standing_privilege.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'zsp_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('zero_standing_privilege.settings');

    // -------------------------------------------------------------------------
    // Approval workflow.
    // -------------------------------------------------------------------------
    $form['approval'] = [
      '#type'  => 'details',
      '#title' => $this->t('Approval Workflow'),
      '#open'  => TRUE,
    ];

    $form['approval']['require_approval'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Require manual approval for elevation requests'),
      '#description'   => $this->t('When enabled, requests are queued for an approver to review. When disabled, all requests are auto-approved immediately.'),
      '#default_value' => $config->get('require_approval') ?? TRUE,
    ];

    // Roles for approvers.
    $roleOptions = $this->getRoleOptions();

    $form['approval']['approver_roles'] = [
      '#type'          => 'checkboxes',
      '#title'         => $this->t('Approver roles'),
      '#description'   => $this->t('Members of these roles may approve or deny elevation requests.'),
      '#options'       => $roleOptions,
      '#default_value' => $config->get('approver_roles') ?? ['administrator'],
      '#states'        => [
        'visible' => [
          ':input[name="require_approval"]' => ['checked' => TRUE],
        ],
      ],
    ];

    $form['approval']['approver_uids'] = [
      '#type'          => 'textfield',
      '#title'         => $this->t('Specific approver UIDs'),
      '#description'   => $this->t('Comma-separated list of user IDs designated as approvers, regardless of their roles.'),
      '#default_value' => implode(', ', (array) ($config->get('approver_uids') ?? [])),
      '#states'        => [
        'visible' => [
          ':input[name="require_approval"]' => ['checked' => TRUE],
        ],
      ],
    ];

    // Auto-approve roles.
    $form['approval']['auto_approve_roles'] = [
      '#type'          => 'checkboxes',
      '#title'         => $this->t('Auto-approve roles'),
      '#description'   => $this->t('Members of these roles receive automatic approval without manual review, even when "Require manual approval" is enabled.'),
      '#options'       => $roleOptions,
      '#default_value' => $config->get('auto_approve_roles') ?? [],
    ];

    // -------------------------------------------------------------------------
    // Elevation duration.
    // -------------------------------------------------------------------------
    $form['duration'] = [
      '#type'  => 'details',
      '#title' => $this->t('Elevation Duration'),
      '#open'  => TRUE,
    ];

    $form['duration']['max_elevation_minutes'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Maximum elevation duration (minutes)'),
      '#description'   => $this->t('Hard upper limit on how long an elevation can last. Requests for longer durations are silently clamped to this value. Default: 240 (4 hours).'),
      '#default_value' => $config->get('max_elevation_minutes') ?? 240,
      '#min'           => 1,
      '#max'           => 43200,
      '#required'      => TRUE,
    ];

    $form['duration']['default_elevation_minutes'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Default elevation duration (minutes)'),
      '#description'   => $this->t('Pre-filled duration on the request form. Default: 60.'),
      '#default_value' => $config->get('default_elevation_minutes') ?? 60,
      '#min'           => 1,
      '#max'           => 43200,
      '#required'      => TRUE,
    ];

    // -------------------------------------------------------------------------
    // Allowed target roles.
    // -------------------------------------------------------------------------
    $form['roles'] = [
      '#type'  => 'details',
      '#title' => $this->t('Allowed Target Roles'),
      '#open'  => TRUE,
    ];

    $form['roles']['allowed_target_roles'] = [
      '#type'          => 'checkboxes',
      '#title'         => $this->t('Roles that may be requested'),
      '#description'   => $this->t('Restrict which roles users may request elevation to. Leave all unchecked to allow requesting any role.'),
      '#options'       => $roleOptions,
      '#default_value' => $config->get('allowed_target_roles') ?? [],
    ];

    // -------------------------------------------------------------------------
    // Email notifications.
    // -------------------------------------------------------------------------
    $form['notifications'] = [
      '#type'  => 'details',
      '#title' => $this->t('Email Notifications'),
      '#open'  => TRUE,
    ];

    $form['notifications']['notify_approvers_on_request'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Notify approvers when a new request is submitted'),
      '#default_value' => $config->get('notify_approvers_on_request') ?? TRUE,
    ];

    $form['notifications']['notify_requester_on_grant'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Notify requester when their elevation is approved'),
      '#default_value' => $config->get('notify_requester_on_grant') ?? TRUE,
    ];

    $form['notifications']['notify_requester_on_deny'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Notify requester when their elevation is denied'),
      '#default_value' => $config->get('notify_requester_on_deny') ?? TRUE,
    ];

    $form['notifications']['notify_requester_on_expiry'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Notify requester when their elevation expires'),
      '#default_value' => $config->get('notify_requester_on_expiry') ?? TRUE,
    ];

    $form['notifications']['from_email'] = [
      '#type'          => 'email',
      '#title'         => $this->t('Notification from email address'),
      '#description'   => $this->t('Leave blank to use the site default.'),
      '#default_value' => $config->get('from_email') ?? '',
    ];

    $form['notifications']['from_name'] = [
      '#type'          => 'textfield',
      '#title'         => $this->t('Notification from name'),
      '#default_value' => $config->get('from_name') ?? 'Zero Standing Privilege',
      '#maxlength'     => 128,
    ];

    $form['notifications']['site_name_in_email'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Prepend site name to notification subject lines'),
      '#default_value' => $config->get('site_name_in_email') ?? TRUE,
    ];

    // -------------------------------------------------------------------------
    // Revocation tokens.
    // -------------------------------------------------------------------------
    $form['tokens'] = [
      '#type'  => 'details',
      '#title' => $this->t('Revocation Tokens'),
      '#open'  => FALSE,
    ];

    $form['tokens']['revocation_token_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Include one-click revocation link in approval emails'),
      '#description'   => $this->t('When enabled, a unique token URL is included in the approval notification email, allowing the requester to self-revoke early.'),
      '#default_value' => $config->get('revocation_token_enabled') ?? TRUE,
    ];

    $form['tokens']['revocation_token_ttl'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Revocation token validity (seconds)'),
      '#description'   => $this->t('Tokens older than this value are no longer accepted. Default: 86400 (24 hours).'),
      '#default_value' => $config->get('revocation_token_ttl') ?? 86400,
      '#min'           => 300,
      '#max'           => 604800,
      '#states'        => [
        'visible' => [
          ':input[name="revocation_token_enabled"]' => ['checked' => TRUE],
        ],
      ],
    ];

    // -------------------------------------------------------------------------
    // Audit log.
    // -------------------------------------------------------------------------
    $form['audit'] = [
      '#type'  => 'details',
      '#title' => $this->t('Audit Log Retention'),
      '#open'  => FALSE,
    ];

    $form['audit']['audit_retention_days'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Audit log retention (days)'),
      '#description'   => $this->t('Number of days to keep completed (non-active) elevation request records. Set to 0 to retain forever.'),
      '#default_value' => $config->get('audit_retention_days') ?? 365,
      '#min'           => 0,
      '#max'           => 3650,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    $maxMin = (int) $form_state->getValue('max_elevation_minutes');
    $defMin = (int) $form_state->getValue('default_elevation_minutes');

    if ($maxMin < 1) {
      $form_state->setErrorByName('max_elevation_minutes', $this->t('Maximum elevation duration must be at least 1 minute.'));
    }

    if ($defMin < 1) {
      $form_state->setErrorByName('default_elevation_minutes', $this->t('Default elevation duration must be at least 1 minute.'));
    }

    if ($defMin > $maxMin) {
      $form_state->setErrorByName(
        'default_elevation_minutes',
        $this->t('Default elevation duration (@def min) cannot exceed maximum (@max min).', [
          '@def' => $defMin,
          '@max' => $maxMin,
        ])
      );
    }

    // Validate UIDs list.
    $uidText = trim($form_state->getValue('approver_uids'));
    if ($uidText !== '') {
      foreach (array_filter(array_map('trim', explode(',', $uidText))) as $uid) {
        if (!ctype_digit($uid)) {
          $form_state->setErrorByName('approver_uids', $this->t('Approver UIDs must be comma-separated integers. "@uid" is not valid.', ['@uid' => $uid]));
        }
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $config = $this->config('zero_standing_privilege.settings');

    // Parse UIDs.
    $uidText = trim($form_state->getValue('approver_uids'));
    $approverUids = $uidText !== ''
      ? array_values(array_filter(array_map('intval', explode(',', $uidText))))
      : [];

    // Filter checkboxes to only selected values.
    $approverRoles     = array_values(array_filter($form_state->getValue('approver_roles') ?? []));
    $autoApproveRoles  = array_values(array_filter($form_state->getValue('auto_approve_roles') ?? []));
    $allowedTargetRoles = array_values(array_filter($form_state->getValue('allowed_target_roles') ?? []));

    $config
      ->set('require_approval', (bool) $form_state->getValue('require_approval'))
      ->set('approver_roles', $approverRoles)
      ->set('approver_uids', $approverUids)
      ->set('auto_approve_roles', $autoApproveRoles)
      ->set('max_elevation_minutes', (int) $form_state->getValue('max_elevation_minutes'))
      ->set('default_elevation_minutes', (int) $form_state->getValue('default_elevation_minutes'))
      ->set('allowed_target_roles', $allowedTargetRoles)
      ->set('notify_approvers_on_request', (bool) $form_state->getValue('notify_approvers_on_request'))
      ->set('notify_requester_on_grant', (bool) $form_state->getValue('notify_requester_on_grant'))
      ->set('notify_requester_on_deny', (bool) $form_state->getValue('notify_requester_on_deny'))
      ->set('notify_requester_on_expiry', (bool) $form_state->getValue('notify_requester_on_expiry'))
      ->set('from_email', trim((string) $form_state->getValue('from_email')))
      ->set('from_name', trim((string) $form_state->getValue('from_name')))
      ->set('site_name_in_email', (bool) $form_state->getValue('site_name_in_email'))
      ->set('revocation_token_enabled', (bool) $form_state->getValue('revocation_token_enabled'))
      ->set('revocation_token_ttl', (int) $form_state->getValue('revocation_token_ttl'))
      ->set('audit_retention_days', (int) $form_state->getValue('audit_retention_days'))
      ->save();

    parent::submitForm($form, $form_state);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Returns an array of role machine names => labels for #checkboxes options.
   *
   * Excludes the anonymous and authenticated built-in roles.
   *
   * @return array<string, string>
   */
  private function getRoleOptions(): array {
    $roles = $this->entityTypeManager->getStorage('user_role')->loadMultiple();
    $options = [];
    foreach ($roles as $role) {
      if (in_array($role->id(), ['anonymous', 'authenticated'], TRUE)) {
        continue;
      }
      $options[$role->id()] = $role->label();
    }
    return $options;
  }

}
