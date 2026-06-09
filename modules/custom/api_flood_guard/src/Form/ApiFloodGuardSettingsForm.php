<?php

declare(strict_types=1);

namespace Drupal\api_flood_guard\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Administration settings form for API Flood Guard.
 *
 * Provides configuration for protected paths, flood thresholds, IP allowlist,
 * IP reputation provider settings, and response options.
 */
final class ApiFloodGuardSettingsForm extends ConfigFormBase {

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
    return ['api_flood_guard.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'api_flood_guard_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('api_flood_guard.settings');

    // Protected paths.
    $form['paths'] = [
      '#type'  => 'details',
      '#title' => $this->t('Protected API Paths'),
      '#open'  => TRUE,
    ];

    $protectedPaths = $config->get('protected_paths') ?? [];
    $pathsText = '';
    foreach ($protectedPaths as $entry) {
      $pathsText .= ($entry['match'] === 'prefix' ? 'prefix:' : 'exact:') . $entry['path'] . "\n";
    }

    $form['paths']['protected_paths'] = [
      '#type'          => 'textarea',
      '#title'         => $this->t('Protected paths'),
      '#description'   => $this->t('One entry per line. Prefix format: <code>prefix:/jsonapi</code>. Exact format: <code>exact:/user/login</code>. Requests matching these paths are subject to flood control.'),
      '#default_value' => trim($pathsText),
      '#rows'          => 8,
    ];

    // Flood thresholds.
    $form['thresholds'] = [
      '#type'  => 'details',
      '#title' => $this->t('Flood Thresholds'),
      '#open'  => TRUE,
    ];

    $form['thresholds']['ip_threshold'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Per-IP request threshold'),
      '#description'   => $this->t('Maximum number of API authentication requests from a single IP address within the IP window before blocking. Default: 100.'),
      '#default_value' => $config->get('ip_threshold') ?? 100,
      '#min'           => 1,
      '#max'           => 10000,
      '#required'      => TRUE,
    ];

    $form['thresholds']['ip_window'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Per-IP time window (seconds)'),
      '#description'   => $this->t('Time window in seconds for the per-IP flood counter. Default: 3600 (1 hour).'),
      '#default_value' => $config->get('ip_window') ?? 3600,
      '#min'           => 60,
      '#max'           => 86400,
      '#required'      => TRUE,
    ];

    $form['thresholds']['user_threshold'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Per-username request threshold'),
      '#description'   => $this->t('Maximum number of API authentication requests for a single username within the username window before blocking. Default: 20.'),
      '#default_value' => $config->get('user_threshold') ?? 20,
      '#min'           => 1,
      '#max'           => 1000,
      '#required'      => TRUE,
    ];

    $form['thresholds']['user_window'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Per-username time window (seconds)'),
      '#description'   => $this->t('Time window in seconds for the per-username flood counter. Default: 900 (15 minutes).'),
      '#default_value' => $config->get('user_window') ?? 900,
      '#min'           => 60,
      '#max'           => 86400,
      '#required'      => TRUE,
    ];

    // Response settings.
    $form['response'] = [
      '#type'  => 'details',
      '#title' => $this->t('Block Response'),
      '#open'  => TRUE,
    ];

    $form['response']['response_code'] = [
      '#type'          => 'select',
      '#title'         => $this->t('HTTP response code'),
      '#description'   => $this->t('HTTP status code returned to blocked requests. 429 (Too Many Requests) is the RFC-compliant choice. Use 503 only if your reverse proxy requires it for throttling.'),
      '#options'       => [
        429 => $this->t('429 Too Many Requests (recommended)'),
        503 => $this->t('503 Service Unavailable'),
      ],
      '#default_value' => $config->get('response_code') ?? 429,
      '#required'      => TRUE,
    ];

    $form['response']['block_message'] = [
      '#type'          => 'textfield',
      '#title'         => $this->t('Block response message'),
      '#description'   => $this->t('Human-readable error detail included in the block response body. Not HTML; safe for API clients.'),
      '#default_value' => $config->get('block_message') ?? 'Too many authentication requests. Please wait before trying again.',
      '#maxlength'     => 500,
      '#required'      => TRUE,
    ];

    // IP Allowlist.
    $form['allowlist_section'] = [
      '#type'  => 'details',
      '#title' => $this->t('IP Allowlist'),
      '#open'  => TRUE,
    ];

    $allowlist = $config->get('allowlist') ?? [];
    $form['allowlist_section']['allowlist'] = [
      '#type'          => 'textarea',
      '#title'         => $this->t('Allowlisted IP addresses and CIDR ranges'),
      '#description'   => $this->t('One entry per line. Accepts individual IPv4/IPv6 addresses and CIDR ranges (e.g. <code>10.0.0.0/8</code>, <code>192.168.1.5</code>, <code>::1</code>). Allowlisted IPs bypass all flood and reputation checks.'),
      '#default_value' => implode("\n", $allowlist),
      '#rows'          => 6,
    ];

    // IP Reputation.
    $form['reputation'] = [
      '#type'  => 'details',
      '#title' => $this->t('IP Reputation'),
      '#open'  => FALSE,
    ];

    $form['reputation']['enabled_provider'] = [
      '#type'          => 'select',
      '#title'         => $this->t('IP reputation provider'),
      '#description'   => $this->t('Select an IP reputation provider to check incoming IPs before flood counters. Select "None" to disable reputation checking.'),
      '#options'       => [
        ''          => $this->t('None (disabled)'),
        'abuseipdb' => $this->t('AbuseIPDB'),
      ],
      '#default_value' => $config->get('reputation_providers.enabled_provider') ?? '',
    ];

    $form['reputation']['abuseipdb'] = [
      '#type'   => 'details',
      '#title'  => $this->t('AbuseIPDB Settings'),
      '#open'   => TRUE,
      '#states' => [
        'visible' => [
          ':input[name="enabled_provider"]' => ['value' => 'abuseipdb'],
        ],
      ],
    ];

    $abuseIpDbConfig = $config->get('reputation_providers.abuseipdb') ?? [];

    // If Key module is available, offer key entity selector.
    $keyModuleAvailable = \Drupal::hasService('key.repository');

    if ($keyModuleAvailable) {
      try {
        /** @var \Drupal\key\KeyRepositoryInterface $keyRepository */
        $keyRepository = \Drupal::service('key.repository');
        $keys = $keyRepository->getKeys();
        $keyOptions = ['' => $this->t('— Enter API key directly —')];
        foreach ($keys as $key) {
          $keyOptions[$key->id()] = $key->label();
        }

        $form['reputation']['abuseipdb']['api_key_id'] = [
          '#type'          => 'select',
          '#title'         => $this->t('AbuseIPDB API key (Key module entity)'),
          '#description'   => $this->t('Select a Key module entity containing your AbuseIPDB API key. Recommended for production environments.'),
          '#options'       => $keyOptions,
          '#default_value' => $abuseIpDbConfig['api_key_id'] ?? '',
        ];
      }
      catch (\Exception) {
        // Key module available but failed — fall through to plain text field.
      }
    }

    $form['reputation']['abuseipdb']['api_key'] = [
      '#type'          => 'password',
      '#title'         => $this->t('AbuseIPDB API key (plain text)'),
      '#description'   => $this->t('Your AbuseIPDB v2 API key. Get a free key at https://www.abuseipdb.com. Leave blank if using the Key module field above.'),
      '#default_value' => $abuseIpDbConfig['api_key'] ?? '',
      '#maxlength'     => 255,
    ];

    $form['reputation']['abuseipdb']['threshold'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Confidence score threshold'),
      '#description'   => $this->t('AbuseIPDB confidence score (0-100) at or above which an IP is blocked. Default: 85.'),
      '#default_value' => $abuseIpDbConfig['threshold'] ?? 85,
      '#min'           => 0,
      '#max'           => 100,
    ];

    $form['reputation']['abuseipdb']['max_age_days'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Maximum report age (days)'),
      '#description'   => $this->t('Maximum age of abuse reports to consider when checking an IP. Passed as maxAgeInDays to the AbuseIPDB API. Default: 30.'),
      '#default_value' => $abuseIpDbConfig['max_age_days'] ?? 30,
      '#min'           => 1,
      '#max'           => 365,
    ];

    $form['reputation']['abuseipdb']['cache_ttl'] = [
      '#type'          => 'number',
      '#title'         => $this->t('Cache TTL (seconds)'),
      '#description'   => $this->t('How long to cache AbuseIPDB responses per IP address. Default: 3600 (1 hour). Set to 0 to disable caching (not recommended in production).'),
      '#default_value' => $abuseIpDbConfig['cache_ttl'] ?? 3600,
      '#min'           => 0,
      '#max'           => 86400,
    ];

    // Debugging.
    $form['debug'] = [
      '#type'  => 'details',
      '#title' => $this->t('Debugging'),
      '#open'  => FALSE,
    ];

    $form['debug']['debug_logging'] = [
      '#type'          => 'checkbox',
      '#title'         => $this->t('Enable debug-level logging'),
      '#description'   => $this->t('Log a DEBUG entry for every allowed request through a protected path. This generates high log volume — enable only for troubleshooting.'),
      '#default_value' => $config->get('debug_logging') ?? FALSE,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    // Validate integer thresholds.
    $ipThreshold = $form_state->getValue('ip_threshold');
    if (!is_numeric($ipThreshold) || (int) $ipThreshold < 1) {
      $form_state->setErrorByName('ip_threshold', $this->t('Per-IP threshold must be a positive integer.'));
    }

    $ipWindow = $form_state->getValue('ip_window');
    if (!is_numeric($ipWindow) || (int) $ipWindow < 60 || (int) $ipWindow > 86400) {
      $form_state->setErrorByName('ip_window', $this->t('Per-IP window must be between 60 and 86400 seconds.'));
    }

    $userThreshold = $form_state->getValue('user_threshold');
    if (!is_numeric($userThreshold) || (int) $userThreshold < 1) {
      $form_state->setErrorByName('user_threshold', $this->t('Per-username threshold must be a positive integer.'));
    }

    $userWindow = $form_state->getValue('user_window');
    if (!is_numeric($userWindow) || (int) $userWindow < 60 || (int) $userWindow > 86400) {
      $form_state->setErrorByName('user_window', $this->t('Per-username window must be between 60 and 86400 seconds.'));
    }

    // Validate response code.
    $responseCode = (int) $form_state->getValue('response_code');
    if (!in_array($responseCode, [429, 503], TRUE)) {
      $form_state->setErrorByName('response_code', $this->t('Response code must be 429 or 503.'));
    }

    // Validate allowlist CIDR entries.
    $allowlistText = trim($form_state->getValue('allowlist'));
    if ($allowlistText !== '') {
      $lines = array_filter(array_map('trim', explode("\n", $allowlistText)));
      foreach ($lines as $line) {
        $ip = str_contains($line, '/') ? explode('/', $line, 2)[0] : $line;
        if (@inet_pton($ip) === FALSE) {
          $form_state->setErrorByName(
            'allowlist',
            $this->t('Invalid IP address or CIDR range: @entry. Each entry must be a valid IPv4 or IPv6 address, optionally with a CIDR prefix length (e.g. 10.0.0.0/8).', ['@entry' => $line])
          );
        }
      }
    }

    // Validate AbuseIPDB threshold.
    $threshold = $form_state->getValue('threshold');
    if ($threshold !== NULL && (!is_numeric($threshold) || (int) $threshold < 0 || (int) $threshold > 100)) {
      $form_state->setErrorByName('threshold', $this->t('AbuseIPDB confidence threshold must be between 0 and 100.'));
    }

    // Validate protected paths.
    $pathsText = trim($form_state->getValue('protected_paths'));
    if ($pathsText !== '') {
      $lines = array_filter(array_map('trim', explode("\n", $pathsText)));
      foreach ($lines as $line) {
        $parts = explode(':', $line, 2);
        if (count($parts) !== 2 || !in_array($parts[0], ['prefix', 'exact'], TRUE)) {
          $form_state->setErrorByName(
            'protected_paths',
            $this->t('Invalid path entry: @entry. Format must be <code>prefix:/path</code> or <code>exact:/path</code>.', ['@entry' => $line])
          );
        }
        elseif (!str_starts_with(trim($parts[1]), '/')) {
          $form_state->setErrorByName(
            'protected_paths',
            $this->t('Path @path must begin with a forward slash.', ['@path' => $parts[1]])
          );
        }
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $config = $this->config('api_flood_guard.settings');

    // Parse protected paths.
    $pathsText = trim($form_state->getValue('protected_paths'));
    $protectedPaths = [];
    if ($pathsText !== '') {
      foreach (array_filter(array_map('trim', explode("\n", $pathsText))) as $line) {
        $parts = explode(':', $line, 2);
        if (count($parts) === 2) {
          $protectedPaths[] = [
            'match' => trim($parts[0]),
            'path'  => trim($parts[1]),
          ];
        }
      }
    }

    // Parse allowlist.
    $allowlistText = trim($form_state->getValue('allowlist'));
    $allowlist = $allowlistText !== ''
      ? array_values(array_filter(array_map('trim', explode("\n", $allowlistText))))
      : [];

    // Build AbuseIPDB config; preserve existing api_key if new one is blank.
    $existingAbuseConfig = $config->get('reputation_providers.abuseipdb') ?? [];
    $newApiKey = trim((string) $form_state->getValue('api_key'));
    $apiKey = $newApiKey !== '' ? $newApiKey : ($existingAbuseConfig['api_key'] ?? '');

    $config
      ->set('protected_paths', $protectedPaths)
      ->set('ip_threshold', (int) $form_state->getValue('ip_threshold'))
      ->set('ip_window', (int) $form_state->getValue('ip_window'))
      ->set('user_threshold', (int) $form_state->getValue('user_threshold'))
      ->set('user_window', (int) $form_state->getValue('user_window'))
      ->set('response_code', (int) $form_state->getValue('response_code'))
      ->set('block_message', trim((string) $form_state->getValue('block_message')))
      ->set('allowlist', $allowlist)
      ->set('reputation_providers.enabled_provider', (string) $form_state->getValue('enabled_provider'))
      ->set('reputation_providers.abuseipdb.api_key', $apiKey)
      ->set('reputation_providers.abuseipdb.api_key_id', trim((string) ($form_state->getValue('api_key_id') ?? '')))
      ->set('reputation_providers.abuseipdb.threshold', (int) ($form_state->getValue('threshold') ?? 85))
      ->set('reputation_providers.abuseipdb.max_age_days', (int) ($form_state->getValue('max_age_days') ?? 30))
      ->set('reputation_providers.abuseipdb.cache_ttl', (int) ($form_state->getValue('cache_ttl') ?? 3600))
      ->set('debug_logging', (bool) $form_state->getValue('debug_logging'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
