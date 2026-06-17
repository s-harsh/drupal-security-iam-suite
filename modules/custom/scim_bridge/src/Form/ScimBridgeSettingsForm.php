<?php

declare(strict_types=1);

namespace Drupal\scim_bridge\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\scim_bridge\Service\ScimAuthenticator;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Administration settings form for the SCIM Bridge module.
 *
 * Provides the global settings UI including:
 *   - Module enabled toggle
 *   - IdP token management (add/remove/toggle tokens)
 *   - Conflict resolution strategy
 *   - Page size limit
 *   - Sync log configuration
 */
final class ScimBridgeSettingsForm extends ConfigFormBase {

  /**
   * The module settings config object name.
   */
  private const CONFIG_NAME = 'scim_bridge.settings';

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
    return [self::CONFIG_NAME];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'scim_bridge_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config(self::CONFIG_NAME);

    $form['global'] = [
      '#type'  => 'details',
      '#title' => $this->t('Global settings'),
      '#open'  => TRUE,
    ];

    $form['global']['enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable SCIM Bridge'),
      '#description'   => $this->t('When unchecked, all SCIM requests are rejected with HTTP 503. Disable during maintenance or initial configuration.'),
      '#default_value' => (bool) $config->get('enabled'),
    ];

    $form['global']['conflict_strategy'] = [
      '#type'          => 'radios',
      '#title'         => $this->t('Conflict resolution strategy'),
      '#description'   => $this->t(
        '<strong>Skip</strong>: when a SCIM POST finds an existing user by userName or email, return that user without modification (HTTP 200). <strong>Update</strong>: merge the incoming attributes into the existing account (HTTP 200).',
      ),
      '#options' => [
        'skip'   => $this->t('Skip — return existing user unchanged'),
        'update' => $this->t('Update — merge incoming attributes into existing user'),
      ],
      '#default_value' => (string) ($config->get('conflict_strategy') ?? 'skip'),
    ];

    $form['global']['max_page_size'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Maximum list page size'),
      '#description'   => $this->t('Hard cap on the number of resources returned per list request regardless of what the IdP requests. Minimum 1, maximum 1000.'),
      '#default_value' => (int) ($config->get('max_page_size') ?? 100),
      '#min'           => 1,
      '#max'           => 1000,
      '#step'          => 1,
      '#required'      => TRUE,
    ];

    // ---------------------------------------------------------------------------
    // IdP Token management
    // ---------------------------------------------------------------------------
    $form['tokens'] = [
      '#type'  => 'details',
      '#title' => $this->t('Identity Provider tokens'),
      '#open'  => TRUE,
      '#description' => $this->t(
        'Each Identity Provider (Okta, Azure AD, Google Workspace, etc.) must be issued a unique Bearer token. Tokens are stored as SHA-256 hashes. Copy the raw token into your IdP configuration immediately — it cannot be retrieved after saving.',
      ),
    ];

    $tokens = (array) ($config->get('idp_tokens') ?? []);
    $tokenCount = $form_state->get('token_count');
    if ($tokenCount === NULL) {
      $tokenCount = max(1, count($tokens));
      $form_state->set('token_count', $tokenCount);
    }

    $form['tokens']['idp_tokens'] = [
      '#type'   => 'table',
      '#header' => [
        $this->t('IdP label'),
        $this->t('Raw token (paste once)'),
        $this->t('Enabled'),
      ],
      '#empty'  => $this->t('No tokens configured.'),
    ];

    for ($i = 0; $i < $tokenCount; $i++) {
      $entry = $tokens[$i] ?? [];
      $form['tokens']['idp_tokens'][$i]['label'] = [
        '#type'          => 'textfield',
        '#default_value' => (string) ($entry['label'] ?? ''),
        '#placeholder'   => $this->t('e.g. Okta Production'),
        '#maxlength'     => 128,
      ];
      $form['tokens']['idp_tokens'][$i]['raw_token'] = [
        '#type'        => 'password',
        '#placeholder' => isset($entry['token']) && $entry['token'] !== '' ? $this->t('(unchanged)') : $this->t('Paste raw token'),
        '#maxlength'   => 255,
        '#description' => isset($entry['token']) && $entry['token'] !== '' ? $this->t('Leave blank to keep the existing token.') : '',
      ];
      $form['tokens']['idp_tokens'][$i]['enabled'] = [
        '#type'          => 'checkbox',
        '#default_value' => (bool) ($entry['enabled'] ?? TRUE),
      ];
    }

    $form['tokens']['add_token'] = [
      '#type'   => 'submit',
      '#value'  => $this->t('Add another token'),
      '#submit' => ['::addTokenRow'],
      '#limit_validation_errors' => [],
      '#ajax'   => [
        'callback' => '::tokenTableCallback',
        'wrapper'  => 'token-table-wrapper',
      ],
    ];

    $form['tokens']['token_table_wrapper'] = [
      '#type'       => 'container',
      '#attributes' => ['id' => 'token-table-wrapper'],
    ];

    // ---------------------------------------------------------------------------
    // Sync log settings
    // ---------------------------------------------------------------------------
    $form['sync_log'] = [
      '#type'  => 'details',
      '#title' => $this->t('Sync log'),
      '#open'  => TRUE,
    ];

    $form['sync_log']['sync_log_enabled'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable sync log'),
      '#description'   => $this->t('Records all SCIM operations in the database for audit and debugging. Disable only on very high-traffic sites.'),
      '#default_value' => (bool) ($config->get('sync_log_enabled') ?? TRUE),
    ];

    $form['sync_log']['sync_log_retention_days'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Sync log retention'),
      '#description'   => $this->t('Number of days to retain sync log entries. Set to 0 to retain forever.'),
      '#default_value' => (int) ($config->get('sync_log_retention_days') ?? 90),
      '#min'           => 0,
      '#step'          => 1,
      '#field_suffix'  => $this->t('days'),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * Ajax callback that returns the token table wrapper.
   *
   * @param array<string, mixed> $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   *
   * @return array<string, mixed>
   *   The token table portion of the form.
   */
  public function tokenTableCallback(array &$form, FormStateInterface $form_state): array {
    return $form['tokens']['idp_tokens'];
  }

  /**
   * Submit handler that adds a new token row to the table.
   *
   * @param array<string, mixed> $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   */
  public function addTokenRow(array &$form, FormStateInterface $form_state): void {
    $count = (int) $form_state->get('token_count');
    $form_state->set('token_count', $count + 1);
    $form_state->setRebuild(TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    $maxPageSize = $form_state->getValue('max_page_size');
    if (!is_numeric($maxPageSize) || (int) $maxPageSize < 1 || (int) $maxPageSize > 1000) {
      $form_state->setErrorByName('max_page_size', $this->t('Maximum page size must be an integer between 1 and 1000.'));
    }

    $retentionDays = $form_state->getValue('sync_log_retention_days');
    if (!is_numeric($retentionDays) || (int) $retentionDays < 0) {
      $form_state->setErrorByName('sync_log_retention_days', $this->t('Sync log retention must be a non-negative integer.'));
    }

    // Validate token entries: label required when raw token is being set.
    $tokenRows = (array) ($form_state->getValue('idp_tokens') ?? []);
    foreach ($tokenRows as $idx => $row) {
      $rawToken = trim((string) ($row['raw_token'] ?? ''));
      $label    = trim((string) ($row['label'] ?? ''));
      if ($rawToken !== '' && $label === '') {
        $form_state->setErrorByName(
          "idp_tokens][$idx][label",
          $this->t('An IdP label is required when providing a token.'),
        );
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $config   = $this->config(self::CONFIG_NAME);
    $existing = (array) ($config->get('idp_tokens') ?? []);

    $tokenRows = (array) ($form_state->getValue('idp_tokens') ?? []);
    $newTokens = [];

    foreach ($tokenRows as $idx => $row) {
      $rawToken = trim((string) ($row['raw_token'] ?? ''));
      $label    = trim((string) ($row['label'] ?? ''));
      if ($label === '' && $rawToken === '') {
        continue;
      }

      $existingHash = (string) ($existing[$idx]['token'] ?? '');
      $hash         = ($rawToken !== '') ? ScimAuthenticator::hashToken($rawToken) : $existingHash;

      if ($hash === '') {
        continue;
      }

      $newTokens[] = [
        'label'   => $label,
        'token'   => $hash,
        'enabled' => (bool) ($row['enabled'] ?? TRUE),
      ];
    }

    $config
      ->set('enabled', (bool) $form_state->getValue('enabled'))
      ->set('conflict_strategy', (string) $form_state->getValue('conflict_strategy'))
      ->set('max_page_size', (int) $form_state->getValue('max_page_size'))
      ->set('idp_tokens', $newTokens)
      ->set('sync_log_enabled', (bool) $form_state->getValue('sync_log_enabled'))
      ->set('sync_log_retention_days', (int) $form_state->getValue('sync_log_retention_days'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
