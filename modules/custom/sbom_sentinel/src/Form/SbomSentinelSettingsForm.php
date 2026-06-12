<?php

declare(strict_types=1);

namespace Drupal\sbom_sentinel\Form;

use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Administration settings form for the SBOM Sentinel module.
 *
 * Exposes the configuration keys from sbom_sentinel.settings:
 *   - enabled: global on/off switch
 *   - composer_lock_path: path to composer.lock
 *   - osv_api_base_url: OSV.dev API base URL
 *   - http_timeout: Guzzle connect + read timeout in seconds
 *   - cron_enabled: weekly cron scan on/off
 *   - email_report_enabled: email report after cron scan
 *   - email_recipient: recipient address for cron reports
 *   - scan_cache_ttl: OSV scan result cache TTL in seconds
 */
final class SbomSentinelSettingsForm extends ConfigFormBase {

  /**
   * The module settings config object name.
   */
  private const CONFIG_NAME = 'sbom_sentinel.settings';

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
    return 'sbom_sentinel_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config(self::CONFIG_NAME);

    $form['global'] = [
      '#type' => 'details',
      '#title' => $this->t('Global settings'),
      '#open' => TRUE,
    ];

    $form['global']['enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable SBOM Sentinel'),
      '#description' => $this->t(
        'When unchecked, the module will not perform OSV.dev scans, run cron jobs, or display risk reports. The admin menu links remain visible but pages will display an informational message.',
      ),
      '#default_value' => (bool) $config->get('enabled'),
    ];

    $form['global']['composer_lock_path'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Path to composer.lock'),
      '#description' => $this->t(
        'Path to <code>composer.lock</code> relative to the Drupal root directory (e.g. <code>../composer.lock</code>). The file must be readable by the web server process.',
      ),
      '#default_value' => (string) $config->get('composer_lock_path'),
      '#required' => TRUE,
      '#maxlength' => 512,
    ];

    $form['api'] = [
      '#type' => 'details',
      '#title' => $this->t('OSV.dev API settings'),
      '#open' => TRUE,
    ];

    $form['api']['osv_api_base_url'] = [
      '#type' => 'textfield',
      '#title' => $this->t('OSV API base URL'),
      '#description' => $this->t(
        'Base URL for the OSV.dev Vulnerability API. Use <code>https://api.osv.dev/v1</code> for the official service. Override only for a local mirror or testing.',
      ),
      '#default_value' => (string) $config->get('osv_api_base_url'),
      '#required' => TRUE,
      '#maxlength' => 255,
    ];

    $form['api']['http_timeout'] = [
      '#type' => 'number',
      '#title' => $this->t('HTTP request timeout'),
      '#description' => $this->t(
        'Maximum wall-clock time in seconds for a single OSV API request (connect + read combined). Minimum 1, maximum 60.',
      ),
      '#default_value' => (int) $config->get('http_timeout'),
      '#required' => TRUE,
      '#min' => 1,
      '#max' => 60,
      '#step' => 1,
      '#field_suffix' => $this->t('seconds'),
    ];

    $form['caching'] = [
      '#type' => 'details',
      '#title' => $this->t('Scan result caching'),
      '#open' => TRUE,
    ];

    $form['caching']['scan_cache_ttl'] = [
      '#type' => 'number',
      '#title' => $this->t('Scan result cache TTL'),
      '#description' => $this->t(
        'How long (in seconds) the full scan result is cached. Default is 3600 (1 hour). Set to 0 to disable caching — each report page visit will trigger fresh OSV API calls for all components.',
      ),
      '#default_value' => (int) $config->get('scan_cache_ttl'),
      '#required' => TRUE,
      '#min' => 0,
      '#step' => 1,
      '#field_suffix' => $this->t('seconds'),
    ];

    $form['cron'] = [
      '#type' => 'details',
      '#title' => $this->t('Cron & email reporting'),
      '#open' => TRUE,
    ];

    $form['cron']['cron_enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable weekly cron scan'),
      '#description' => $this->t(
        'When checked, a full SBOM scan is performed automatically once per week during Drupal cron runs. The results are cached and displayed in the admin report.',
      ),
      '#default_value' => (bool) $config->get('cron_enabled'),
    ];

    $form['cron']['email_report_enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Send email report after cron scan'),
      '#description' => $this->t(
        'When checked, a summary email listing vulnerable components is sent after each weekly cron scan.',
      ),
      '#default_value' => (bool) $config->get('email_report_enabled'),
      '#states' => [
        'visible' => [':input[name="cron_enabled"]' => ['checked' => TRUE]],
      ],
    ];

    $form['cron']['email_recipient'] = [
      '#type' => 'email',
      '#title' => $this->t('Email recipient'),
      '#description' => $this->t(
        'Email address to receive the weekly scan report. Leave blank to use the site email address configured in <em>Administration → Configuration → System → Site information</em>.',
      ),
      '#default_value' => (string) $config->get('email_recipient'),
      '#maxlength' => 254,
      '#states' => [
        'visible' => [
          ':input[name="cron_enabled"]' => ['checked' => TRUE],
          ':input[name="email_report_enabled"]' => ['checked' => TRUE],
        ],
      ],
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    parent::validateForm($form, $form_state);

    $httpTimeout = $form_state->getValue('http_timeout');
    if (!is_numeric($httpTimeout) || (int) $httpTimeout < 1 || (int) $httpTimeout > 60) {
      $form_state->setErrorByName(
        'http_timeout',
        $this->t('HTTP timeout must be an integer between 1 and 60.'),
      );
    }

    $cacheTtl = $form_state->getValue('scan_cache_ttl');
    if (!is_numeric($cacheTtl) || (int) $cacheTtl < 0) {
      $form_state->setErrorByName(
        'scan_cache_ttl',
        $this->t('Scan result cache TTL must be a non-negative integer.'),
      );
    }

    $apiBaseUrl = trim((string) $form_state->getValue('osv_api_base_url'));
    if (!UrlHelper::isValid($apiBaseUrl, absolute: true)) {
      $form_state->setErrorByName(
        'osv_api_base_url',
        $this->t('The OSV API base URL must be a valid absolute URL (e.g. https://api.osv.dev/v1).'),
      );
    }

    $composerLockPath = trim((string) $form_state->getValue('composer_lock_path'));
    if ($composerLockPath === '') {
      $form_state->setErrorByName(
        'composer_lock_path',
        $this->t('The path to composer.lock must not be empty.'),
      );
    }

    $emailRecipient = trim((string) $form_state->getValue('email_recipient'));
    if ($emailRecipient !== '' && !filter_var($emailRecipient, FILTER_VALIDATE_EMAIL)) {
      $form_state->setErrorByName(
        'email_recipient',
        $this->t('The email recipient address is not a valid email address.'),
      );
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->config(self::CONFIG_NAME)
      ->set('enabled', (bool) $form_state->getValue('enabled'))
      ->set('composer_lock_path', trim((string) $form_state->getValue('composer_lock_path')))
      ->set('osv_api_base_url', trim((string) $form_state->getValue('osv_api_base_url')))
      ->set('http_timeout', (int) $form_state->getValue('http_timeout'))
      ->set('scan_cache_ttl', (int) $form_state->getValue('scan_cache_ttl'))
      ->set('cron_enabled', (bool) $form_state->getValue('cron_enabled'))
      ->set('email_report_enabled', (bool) $form_state->getValue('email_report_enabled'))
      ->set('email_recipient', trim((string) $form_state->getValue('email_recipient')))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
